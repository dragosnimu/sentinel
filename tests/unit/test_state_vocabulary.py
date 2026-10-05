"""One state, one name — across every surface that counts or lists findings.

What goes wrong for the operator if it fails: the same state is called "fără date" on the
dashboard card, "gri" on the pill of the vulnerabilities page and "Nedecis" on the row one
click later (measured 5 Oct 2026, in those words); the reports said "Roșii (Act)" where the
row said "Acum"; the "became red" alert said "roșii" and the list "Acum". A reader who meets
three words learns that the page is inconsistent, or that there are three states.

The names live in ONE place (`risk_view.COLOR_STATE_RO`, built from `DECISION_LABEL_RO`). This
reads the text each surface actually produces — the operator's words, not a variable name —
and fails if a surface carries a colour word or "fără date" as the NAME of a state, or lacks
the name the row uses. Colour words stay valid as filter ARGUMENTS (`?culoare=gri`,
`/vulnerabilitati gri`) and in the tooltip of a pill, which is why those are not scanned here.
"""

from __future__ import annotations

import asyncio
import re

import pytest

from sentinel.scan import announce
from sentinel.scan import risk_view as rv
from sentinel.telegram import views
from tests.unit.test_reports_page import _client, _kpi_cards, stub  # noqa: F401  (fixture)

#: The state names the rows use, taken from the label source and not typed again here.
ACUM, CURAND, NEDECIS = (rv.COLOR_STATE_RO[c] for c in ("red", "amber", "grey"))
CICLUL = rv.COLOR_STATE_RO["green"]

#: Words that used to be the NAME of a state somewhere. "fără date" is only banned where it
#: is the old count/legend form (followed by a separator or closing bracket), because
#: "fără date CISA" is a missing datum, not a state.
OLD_NAMES = re.compile(
    r"\broșii\b|\broșie\b|\bgalbene\b|\bverzi\b|\bGRI\b|\bGri\b|Fără date \(gri\)"
    r"|\bfără date\b(?! (?:CISA|păstrate|suficiente))")


def _clean(text: str) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", text).split())


def _assert_only_the_state_names(surface: str, text: str, *names: str) -> None:
    text = _clean(text)
    assert text, f"{surface}: empty text is a vacuous pass"
    for name in names:
        assert name in text, f"{surface} does not say {name!r}: {text[:300]}"
    found = OLD_NAMES.findall(text)
    assert not found, f"{surface} still names a state {found!r}: {text[:300]}"


def test_the_dashboard_card_names_the_states():
    from tests.unit.test_dashboard_render import _context, _env
    from tests.unit.test_dashboard_risk_cards import _card, _kpi

    html = _env().get_template("dashboard.html").render(**_context(
        kpi=_kpi(vuln_rosii=1, vuln_galbene=3, vuln_gri=27, vuln_kev=2)))
    _assert_only_the_state_names("dashboard card", _card(html), ACUM, CURAND, NEDECIS)


def test_the_report_page_card_and_list_name_the_states(stub):  # noqa: F811
    with _client(stub) as c:
        body = c.get("/reports").text
    card = _kpi_cards(body)["Vulnerabilități deschise"]
    _assert_only_the_state_names("report card", card, ACUM, CURAND, NEDECIS)
    # The list under the card: every state with the CISA name beside it where there is one.
    lines = [ln for ln in _clean(body).split("Deschise acum")[1:2]]
    assert lines, "the report list is not on the page"
    _assert_only_the_state_names("report list", lines[0][:400], "Acum (Act)", "Curând (Attend)",
                                 NEDECIS)


@pytest.mark.parametrize("word,state", [
    ("rosii", ACUM), ("roșii", ACUM), ("galbene", CURAND), ("gri", NEDECIS), ("acum", ACUM),
    ("curând", CURAND), ("nedecis", NEDECIS), ("verzi", CICLUL)])
def test_a_telegram_filter_titles_the_list_with_the_state_name_not_the_word_typed(word, state):
    """`/vulnerabilitati gri` is typed with the colour; the header of the answer names the state."""
    f = views.parse_vuln_filter(word)
    assert f.warning is None and f.colors is not None, word
    _assert_only_the_state_names(f"filter {word!r}", f"{f.title} {f.scope}", state)


def _vuln_insight(**row):
    from sentinel.analytics import insights as ins
    from tests.unit.test_insights import _fnd

    return asyncio.run(ins._vuln_insight(_fnd(**row)))[0]


def test_the_vulnerability_insight_cards_use_the_state_names():
    kev = _vuln_insight(deschise=50, kev=43, rosii=2, galbene=3, gri=5)
    _assert_only_the_state_names("insight KEV", f"{kev.title} {kev.detail}", ACUM, CURAND, NEDECIS)
    red = _vuln_insight(deschise=50, rosii=1, gri=4)
    _assert_only_the_state_names("insight red", f"{red.title} {red.detail}", ACUM)
    amber = _vuln_insight(deschise=50, galbene=3, gri=25)
    _assert_only_the_state_names("insight amber", f"{amber.title} {amber.detail}", CURAND, NEDECIS)
    quiet = _vuln_insight(deschise=812, gri=25)
    _assert_only_the_state_names("insight quiet", f"{quiet.title} {quiet.detail}", CICLUL, NEDECIS)


@pytest.mark.parametrize("how_many", [1, 2])
def test_the_became_red_alert_names_the_state_not_the_colour(how_many):
    """Singular and plural are two branches of the message title; both are read."""
    findings = [{"id": i, "cve": f"CVE-2025-{i}", "package": "next", "priority": 99 - i,
                 "risk": {"decision": "act", "epss": {"p": 0.992}}} for i in range(how_many)]
    msg = announce.build_red_message(findings, host="gazda")
    _assert_only_the_state_names(f"announce_red x{how_many}", msg, ACUM, "Acum (Act)")


def test_the_maintenance_pass_detail_names_the_states(monkeypatch):
    from sentinel.scan import enrich
    from sentinel.services import maintenance_service as ms

    async def done(_db, _cfg, **kw):
        return {"status": "completed", "findings": 812, "changed": 3,
                "colors": {"red": 1, "amber": 3, "grey": 25, "green": 783}, "sources": {}}
    monkeypatch.setattr(enrich, "run", done)
    detail, _ = asyncio.run(ms.assess_risk(object(), object()))
    _assert_only_the_state_names("maintenance detail", detail, ACUM, CURAND, NEDECIS, CICLUL)


def test_the_selfcheck_says_nedecis_where_it_used_to_say_gri():
    from sentinel.selfcheck import checks
    from tests.unit.test_selfcheck_risk import _DB, _by_key, _canary, _row

    never = _by_key(asyncio.run(checks.check_risk_intel(_DB([]))))["risk:pass"]
    _assert_only_the_state_names("selfcheck: never evaluated", never.detail, NEDECIS)
    rows = [_row("risk", 0.5, detail={"colors": {"red": 1, "grey": 25, "green": 783},
                                      "findings": 809}),
            _row("epss", 5.0), _row("vulnrichment", 2.0), _canary(), _row("redhat", 3.0),
            _row("osv", 3.0)]
    healthy = _by_key(asyncio.run(checks.check_risk_intel(_DB(rows))))["risk:pass"]
    _assert_only_the_state_names("selfcheck: healthy pass", healthy.detail, NEDECIS)
    silent = _by_key(asyncio.run(checks.check_risk_intel(_DB([_row("risk", 0.1)]))))
    _assert_only_the_state_names("selfcheck: no vulnrichment row",
                                 silent["risk:vulnrichment"].detail, NEDECIS)


def test_the_selfcheck_failing_source_branches_name_the_state_too():
    """The selfcheck writes the state's name in FIVE messages. Three are read above; these are
    the other two — a CISA Vulnrichment whose lookups fail and a vendor (Red Hat) whose pass
    aborted — which tell the operator what the failure costs ("CVE-urile noi rămân
    «Nedecis»"). Each is a literal in `checks.py`, so a rename of the state in the label
    source leaves them naming a state no row carries, and no other test reads these two."""
    from sentinel.selfcheck import checks
    from tests.unit.test_selfcheck_risk import _DB, _by_key, _canary, _row

    vr = _by_key(asyncio.run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("vulnrichment", 1.0, error="HTTP 503", detail={"aborted": True}),
         _canary()]))))["risk:vulnrichment"]
    assert vr.status == "degraded", vr          # the branch under test, not another one
    _assert_only_the_state_names("selfcheck: vulnrichment failing", vr.detail, NEDECIS)
    vendor = _by_key(asyncio.run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("redhat", 1.0, error="HTTP 503",
                                 detail={"aborted": True, "errors": 5, "deferred": 15})]))))
    assert vendor["risk:redhat"].status == "degraded", vendor["risk:redhat"]
    _assert_only_the_state_names("selfcheck: vendor failing", vendor["risk:redhat"].detail, NEDECIS)


def test_the_telegram_dashboard_line_names_the_states(monkeypatch):
    from tests.unit import test_telegram_risk as ttr
    from tests.unit import test_telegram_views as tv

    monkeypatch.setattr(views.insights_mod, "collect", ttr._async([]))
    monkeypatch.setattr(views.insights_mod, "posture", ttr._async(
        {"level": "good", "verdict": "ok", "atacatori": 0, "evenimente": 0}))
    monkeypatch.setattr(views.aggregate, "kpis", ttr._async(
        {**tv._KPI, "vuln_deschise": 812, "vuln_kev": 2, "vuln_rosii": 1,
         "vuln_galbene": 3, "vuln_gri": 0}))
    monkeypatch.setattr(views.aggregate, "deltas", ttr._async({}))
    monkeypatch.setattr(views.aggregate, "service_health", ttr._async({}))
    monkeypatch.setattr(views.aggregate, "top_attackers", ttr._async([]))
    monkeypatch.setattr(views.aggregate, "by_country", ttr._async([]))
    upd, msg = ttr._update()
    ttr.run(views.cmd_dashboard(upd, ttr._ctx(tv._DashDB())))
    line = [ln for ln in msg.sent[0].splitlines() if ln.startswith("Vulnerabilități:")][0]
    _assert_only_the_state_names("telegram dashboard line", line, ACUM, CURAND, NEDECIS)


def test_the_telegram_help_maps_each_filter_word_to_the_state_it_really_brings():
    """/ajutor tells the operator "gri = Nedecis". That mapping was a literal in `HELP`: change
    the state's name (or what a word filters to) and /ajutor goes on teaching the old one —
    the one place the word and the state meet. Read here from the HELP text itself, then each
    word is run through the parser the command uses."""
    line = [ln for ln in views.HELP.splitlines() if ln.startswith("/vulnerabilitati")][0]
    pairs = [p.split(" = ", 1) for p in line[line.rindex("(") + 1:line.rindex(")")].split(", ")]
    # Positive control: the extraction found the four colour words (an empty list would pass).
    assert [w for w, _ in pairs] == ["rosii", "galbene", "gri", "verzi"], pairs
    for word, name in pairs:
        parsed = views.parse_vuln_filter(word)
        assert parsed.warning is None and parsed.colors is not None and len(parsed.colors) == 1, word
        assert name == rv.COLOR_STATE_RO[parsed.colors[0]], (word, name)
    # The words on the left of "=" are filter ARGUMENTS (colour words are valid there); what is
    # on the right is the state's name, and only that is scanned for the old names.
    _assert_only_the_state_names("telegram help", ", ".join(n for _, n in pairs),
                                 ACUM, CURAND, NEDECIS, CICLUL)


@pytest.mark.parametrize("risk", [
    {"decision": None, "missing": []},
    {"decision": None, "missing": ["xx"]},
    {"decision": None, "missing": ["assessment_error"]},
    {"decision": None, "missing": ["epss"]},
    {"decision": None, "missing": ["vulnrichment", "epss"]},
    {"decision": None},
])
def test_a_grey_list_row_and_a_grey_table_cell_say_the_same_thing_about_the_same_row(risk):
    """The Telegram list row said "fără date" — the old NAME of the state, which the rows no
    longer carry — for a grey with no code, an unknown code or `assessment_error`, while the
    panel cell for the very same row said "decizia nu se poate lua" / the code. Two readings of
    one `risk.missing`. The list row gives the first reason, in the cell's words."""
    row = rv.one_liner("grey", risk)
    cell = rv.reason_line("grey", risk)
    assert cell.split(", ")[0] == row, (row, cell)
    assert not OLD_NAMES.findall(row), row


def test_every_code_the_vocabulary_knows_reads_the_same_on_the_row_and_in_the_cell():
    """No code is allowed to be read through a table the other surface does not use."""
    assert rv._MISSING_RO, "positive control: the vocabulary is not empty"
    for code in rv._MISSING_RO:
        risk = {"decision": None, "missing": [code]}
        assert rv.one_liner("grey", risk) == rv.reason_line("grey", risk), code
