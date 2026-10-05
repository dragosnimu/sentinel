"""The traffic light on the phone: list rows, filters, the detail view, the dashboard.

What goes wrong for the operator if these fail: a list where every row is the same
colour (so the first screen no longer answers "how bad is it"), a filter word the
help offers and the command does not obey, a detail view that drops CVSS/EPSS for
a finding the pass has not reached yet, or a grey that does not say why.

Reuses the repository fake from `test_telegram_views.py` (it implements the
filters and LIMIT for real, in SQL order) instead of writing a second one.
"""

from __future__ import annotations

import re

import pytest

from sentinel.telegram import views
from tests.unit.test_telegram_views import (
    _FINDING, _Findings, _async, _ctx, _update, run)


def _row(i, color, decision, **over):
    risk = over.pop("risk", {"decision": decision,
                             "points": {"exploitation": {"value": "active", "basis": "kev"}}})
    return {**_FINDING, "id": i, "risk_color": color, "risk_decision": decision,
            "priority": 100 - i, "risk": risk, **over}


def _sent(monkeypatch, rows, args=None):
    corpus = _Findings(rows).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vulns(upd, _ctx(None, args)))
    return msg.sent[0], corpus


def test_every_row_wears_its_own_colour_and_a_one_line_reason(monkeypatch):
    rows = [_row(1, "red", "act", kev=True),
            _row(2, "amber", "attend", risk={"decision": "attend",
                 "points": {"exploitation": {"value": "active", "basis": "epss"}},
                 "epss": {"p": 0.92}}),
            _row(3, "grey", None, risk={"decision": None, "missing": ["epss"]}),
            _row(4, "green", "track", risk={"decision": "track"})]
    text, _ = _sent(monkeypatch, rows)
    line = {int(m.group(2)): m.group(1)
            for m in re.finditer(r"(🔴|🟡|⚪|🟢) <b>#(\d+)</b>", text)}
    assert line == {1: "🔴", 2: "🟡", 3: "⚪", 4: "🟢"}
    assert "exploatat activ (KEV)" in text and "EPSS 92,0%" in text and "fără EPSS" in text


def test_the_list_legend_maps_each_label_to_its_ssvc_name_and_says_what_grey_means(monkeypatch):
    """The legend is the only place a Telegram list row can learn that "Curând" is CISA's
    "Attend": the rows themselves carry just the colour dot. It once said "🟢 De urmărit
    (Track)" while `headline` and `/vuln` said "Ciclul obișnuit" for Track, so the operator
    was handed the wrong mapping on the one channel with nothing else to go on — and the
    test pinned that same wrong string, green by construction.

    Pinned against the label SOURCES, not a copied literal: every `headline(...)` the rows
    and the headline of `/vuln` can print, with the SSVC name `/vuln` prints beside it."""
    from sentinel.scan import risk_view as rv, ssvc

    text, _ = _sent(monkeypatch, [_row(1, "amber", "attend")])
    for decision in ssvc.DECISIONS:
        color = ssvc.COLOR_OF[decision]
        entry = f"{rv.headline(color, decision)} ({rv.ssvc_name(decision)})"
        assert entry in text, (decision, entry)
        # The same pairing the detail view of that decision prints.
        detail = f"Decizie CISA SSVC: {rv.ssvc_name(decision)} ({rv.DECISION_LABEL_RO[decision]})"
        assert rv.why_lines({"decision": decision})[0] == detail
    grey = rv.headline("grey", None)
    assert grey in text
    # Grey must still read as missing data there, not as an unfinished decision.
    assert f"{grey} (lipsesc date)" in text
    # The wrong mapping that shipped, by name: "De urmărit" is Track*, never Track.
    assert "De urmărit (Track)" not in text
    assert "De urmărit* (Track*)" in text and "Ciclul obișnuit (Track)" in text


def test_a_row_without_a_colour_is_drawn_grey_not_green(monkeypatch):
    """`DEFAULT 'grey'`: a row the pass has not reached is "no data"."""
    text, _ = _sent(monkeypatch, [{**_FINDING, "id": 9, "priority": 5}])
    assert re.search(r"⚪ <b>#9</b>", text), text[:300]
    assert not re.search(r"🟢 <b>#9</b>", text)


@pytest.mark.parametrize("word,color", [
    ("rosii", "red"), ("roșii", "red"), ("galbene", "amber"), ("gri", "grey"),
    ("verzi", "green"), ("verde", "green"), ("fara-nimic", None)])
def test_the_colour_words_filter_in_sql_before_the_limit(monkeypatch, word, color):
    """`/vulnerabilitati gri` is the question "what could I not evaluate"; filtered
    after the cut it would answer "the greys among the top 20", i.e. none."""
    rows = [_row(i, "green", "track", priority=100 - i) for i in range(1, 30)]
    rows += [_row(100, "grey", None, priority=1, risk={"decision": None, "missing": ["cve"]}),
             _row(101, "red", "act", priority=2),
             _row(102, "amber", "attend", priority=3)]
    text, corpus = _sent(monkeypatch, rows, [word])
    if color is None:
        assert "Filtru neînțeles" in text and corpus.calls[-1]["colors"] is None
        return
    assert corpus.calls[-1]["colors"] == [color]
    ids = {int(i) for i in re.findall(r"<b>#(\d+)</b>", text)}
    if color == "green":
        # How many 20 rows FIT depends on the message budget; what matters is that
        # only greens came back and neither the grey nor the red did.
        assert ids and ids <= set(range(1, 30)) and not ({100, 101, 102} & ids), (word, ids)
    else:
        assert ids == {"grey": {100}, "red": {101}, "amber": {102}}[color], (word, ids)


def test_every_announced_filter_word_is_understood_including_the_colours():
    assert {"rosii", "galbene", "gri", "verzi"} <= set(views.FILTER_WORDS)
    for word in ("rosii", "galbene", "gri", "verzi"):
        f = views.parse_vuln_filter(word)
        assert f.warning is None and f.colors is not None and f.filtered


def test_the_colour_pills_ignore_the_colour_filter_so_they_never_read_zero(monkeypatch):
    rows = [_row(1, "red", "act"), _row(2, "green", "track"), _row(3, "grey", None)]
    text, _ = _sent(monkeypatch, rows, ["rosii"])
    pills = text.splitlines()[1]
    assert "🔴 1" in pills and "⚪ 1" in pills and "🟢 1" in pills, pills


# --- the detail --------------------------------------------------------------------
def _detail(monkeypatch, row):
    _Findings([row]).install(monkeypatch)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, [str(row["id"])])))
    return msg.sent[0]


def test_the_detail_gives_the_four_points_the_sources_and_the_decision(monkeypatch):
    risk = {"decision": "attend", "reboot_pending": True, "decision_before_reboot": "act",
            "points": {"exploitation": {"value": "active", "basis": "kev"},
                       "automatable": {"value": "no", "basis": "cvss_vector"},
                       "technical_impact": {"value": "total", "basis": "cvss_vector"},
                       "mission": {"value": "medium", "basis": "asset_criticality"}},
            "cvss": {"source": "redhat", "score": 7.5},
            "epss": {"p": 0.0045, "percentile": 0.3682, "date": "2026-10-01"}}
    text = _detail(monkeypatch, _row(42, "amber", "attend", risk=risk, kev=True))
    assert "🟡 Curând" in text and "Attend — accelerat" not in text
    assert "Decizie CISA SSVC: Attend (Curând)" in text
    assert "exploatat activ · neautomatizabil · impact total · misiune medie" in text
    assert "CVSS 7,5 (Red Hat) · EPSS 0,45% (percentila 37)" in text
    assert "urgența a coborât o treaptă" in text


def test_a_grey_detail_says_what_is_missing_and_how_bad_it_could_be(monkeypatch):
    risk = {"decision": None, "missing": ["epss"], "possible": ["track", "attend"],
            "points": {"exploitation": {"value": None}, "automatable": {"value": "yes"},
                       "technical_impact": {"value": "partial"}, "mission": {"value": "medium"}}}
    text = _detail(monkeypatch, _row(42, "grey", None, risk=risk))
    assert "<b>⚪ Nedecis</b> — fără EPSS" in text, "the headline lost the missing datum"
    assert "lipsește EPSS (nu există încă pentru acest CVE)" in text
    assert "ar putea fi între Track și Attend" in text, "the long reasoning has no home"
    assert "? exploatare" in text


def test_a_never_evaluated_row_still_shows_the_scanners_cvss_and_epss(monkeypatch):
    """The detail used to print `CVSS`/`EPSS` from the columns. A row the pass has
    not reached has empty `risk` but real columns: they must not vanish."""
    text = _detail(monkeypatch, {**_FINDING, "cvss": 8.1, "epss": 0.42, "epss_percentile": 0.97})
    assert "CVSS 8.1" in text and "EPSS 42,0% (percentila 97)" in text
    assert "Încă neevaluată" in text


def test_the_vendors_prose_is_shown_escaped_and_bounded(monkeypatch):
    _Findings([_row(42, "green", "track", ecosystem="rpm")]).install(monkeypatch)

    async def prose(db, row):
        return ("<img src=x onerror=1> " + "word " * 300, "Red Hat")
    monkeypatch.setattr(views.findings_repo, "vendor_justification", prose)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    text = msg.sent[0]
    assert "<img" not in text and "&lt;img" in text
    assert text.count("word") <= 130, "the vendor's prose was not bounded"
    assert "Red Hat:" in text


def test_a_failing_justification_lookup_never_costs_the_operator_the_detail(monkeypatch):
    _Findings([_row(42, "green", "track")]).install(monkeypatch)

    async def boom(db, row):
        raise RuntimeError("db hiccup")
    monkeypatch.setattr(views.findings_repo, "vendor_justification", boom)
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx(None, ["42"])))
    assert "Vulnerabilitate #42" in msg.sent[0]


# --- the dashboard -----------------------------------------------------------------
def test_the_dashboard_line_carries_the_colours_and_always_the_grey(monkeypatch):
    from tests.unit import test_telegram_views as tv

    monkeypatch.setattr(views.insights_mod, "collect", _async([]))
    monkeypatch.setattr(views.insights_mod, "posture", _async(
        {"level": "good", "verdict": "ok", "atacatori": 0, "evenimente": 0}))
    monkeypatch.setattr(views.aggregate, "kpis", _async(
        {**tv._KPI, "vuln_deschise": 812, "vuln_kev": 2, "vuln_rosii": 1,
         "vuln_galbene": 3, "vuln_gri": 0}))
    monkeypatch.setattr(views.aggregate, "deltas", _async({}))
    monkeypatch.setattr(views.aggregate, "service_health", _async({}))
    monkeypatch.setattr(views.aggregate, "top_attackers", _async([]))
    monkeypatch.setattr(views.aggregate, "by_country", _async([]))
    upd, msg = _update()
    run(views.cmd_dashboard(upd, _ctx(tv._DashDB())))
    line = [ln for ln in msg.sent[0].splitlines() if ln.startswith("Vulnerabilități:")][0]
    assert line == ("Vulnerabilități: 812 deschise · 🔴 Acum 1 · 🟡 Curând 3 · ⚪ Nedecis 0 "
                    "· 🔥 2 KEV"), line


# ---------------------------------------------------------------------------
# Sentinel's own overlay: labelled in the list, in the legend and in the detail
# ---------------------------------------------------------------------------
_OVERLAY_RISK = {
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


def test_the_list_marks_an_overlay_row_whole_and_explains_the_mark_once(monkeypatch):
    """A 🟡 the SSVC tree did not give must not look like every other 🟡. The row
    carries the reason in the 24 characters Telegram leaves it, and the legend
    (only when such a row is on screen) says what the mark means."""
    rows = [_row(1, "amber", "attend", risk=_OVERLAY_RISK),
            _row(2, "amber", "attend", risk={"decision": "attend",
                 "points": {"exploitation": {"value": "active", "basis": "kev"}}})]
    text, _ = _sent(monkeypatch, rows)
    block1 = text.split("#2</b>")[0]
    assert "regula Sentinel · EPSS 99,2%" in block1, text
    assert "regula Sentinel ·" not in text.split("#2</b>", 1)[1].split("\n/vuln")[0]
    assert "„regula Sentinel” = urcat de o regulă a Sentinel" in text
    assert "nu de SSVC și nu de FIRST" in text


def test_the_legend_about_the_overlay_is_absent_when_no_row_has_one(monkeypatch):
    text, _ = _sent(monkeypatch, [_row(1, "amber", "attend"), _row(2, "green", "track")])
    assert "regula Sentinel" not in text


def test_the_detail_of_an_overlay_row_says_it_is_sentinels_rule_and_what_ssvc_said(monkeypatch):
    text = _detail(monkeypatch, _row(7, "amber", "attend", risk=_OVERLAY_RISK))
    assert "🟡 Curând · regula Sentinel" in text
    assert "REGULI A SENTINEL" in text
    assert "SSVC singur ar fi dat Track." in text
