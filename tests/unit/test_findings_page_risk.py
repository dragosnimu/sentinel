"""The Findings page's traffic light, driven through the real app.

Same arrangement as `test_findings_page.py` (real middleware, router and Jinja
templates; only the database is a stub that really filters), reused on purpose:
a second harness would be a second place for the stub and the SQL to drift apart.

What goes wrong for the operator if these fail:

  * a finding nobody could evaluate drawn green, or a grey that says nothing
    about why;
  * a colour count that disagrees with the rows below it, or that goes to zero
    the moment one colour is selected;
  * the page claiming a mission it never assumed (every finding is evaluated as
    Mission = medium today, and the page has to say so);
  * a hostile string inside `findings.risk` becoming live markup.
"""

from __future__ import annotations

import datetime
import html as html_mod
import re
from collections import Counter

from sentinel.scan import risk_view as rv
from sentinel.scan import ssvc
from sentinel.web.routers import findings as findings_router
from tests.unit.test_findings_page import StubDB, _finding, _page


class ColorStubDB(StubDB):
    """`StubDB` that also understands the colour clause of `list_open`/`open_counts`.

    Parameters are consumed in the order the SQL appends them (scanner, then
    severity, then colour, then LIMIT/OFFSET), so the stub reads them the same
    way instead of guessing by position.
    """

    @staticmethod
    def _split(sql: str, a: tuple, *, paged: bool):
        args = list(a)
        scanners = args.pop(0) if "coalesce(f.scanner, '') = ANY(" in sql \
            or "coalesce(scanner, '') = ANY(" in sql else None
        colors = args.pop(0) if "risk_color = ANY(" in sql else None
        limit = offset = None
        if paged:
            limit, offset = args[0], args[1]
        return scanners, colors, limit, offset

    @staticmethod
    def _by_color(rows, colors):
        if colors is None:
            return rows
        return [r for r in rows if (r.get("risk_color") or "grey") in colors]

    async def fetch(self, sql: str, *a):
        if "FROM findings f LEFT JOIN assets" in sql:
            self.seen_sql.append((sql, a))
            scanners, colors, limit, offset = self._split(sql, a, paged=True)
            rows = sorted(self._by_color(self._filter(self.all, scanners), colors),
                          key=lambda r: (-r["priority"], -r["id"]))
            return rows[offset:offset + limit]
        if "GROUP BY severity" in sql:
            self.seen_sql.append((sql, a))
            scanners, colors, _, _ = self._split(sql, a, paged=False)
            rows = self._by_color(self._filter(self.all, scanners), colors)
            return [{"severity": s, "n": n}
                    for s, n in Counter(r["severity"] for r in rows).items()]
        if "GROUP BY risk_color" in sql:
            self.seen_sql.append((sql, a))
            scanners, _, _, _ = self._split(sql, a, paged=False)
            rows = self._filter(self.all, scanners)
            return [{"risk_color": c, "n": n}
                    for c, n in Counter(r.get("risk_color") or "grey" for r in rows).items()]
        return await super().fetch(sql, *a)

    async def fetchval(self, sql: str, *a):
        if "status = 'open' AND kev" in sql:
            scanners, colors, _, _ = self._split(sql, a, paged=False)
            rows = self._by_color(self._filter(self.all, scanners), colors)
            return sum(1 for r in rows if r["kev"])
        return await super().fetchval(sql, *a)


def _rows() -> list[dict]:
    """1 red, 1 amber, 2 grey, 3 green — a hand-sized copy of the production shape
    (the measured one on 2 Oct 2026 was 1 / 3 / 25 / 783)."""
    spec = [("red", "act", 95), ("amber", "attend", 70), ("grey", None, 45),
            ("grey", None, 44), ("green", "track", 10), ("green", "track", 9),
            ("green", "track_star", 25)]
    return [_finding(id=i + 1, package=f"pkg-{i + 1}", priority=prio, risk_color=color,
                     risk_decision=decision, cve=f"CVE-2026-{1000 + i}",
                     risk={"decision": decision, "missing": ["epss"] if color == "grey" else [],
                           "possible": ["track", "attend"] if color == "grey" else None,
                           "points": {"exploitation": {"value": "active", "basis": "kev"}},
                           "reboot_pending": i == 1})
            for i, (color, decision, prio) in enumerate(spec)]


def _pill(html: str, label: str) -> str:
    """The text of the colour pill whose state name starts with `label` ("🔴 Acum 1")."""
    for m in re.finditer(r'<a href="[^"]+" class="pill[^"]*"[^>]*>([^<]*)</a>', html):
        text = m.group(1).strip()
        emoji, _, rest = text.partition(" ")
        if emoji in ("🔴", "🟡", "⚪", "🟢") and rest.startswith(label):
            return text
    raise AssertionError(f"nicio pastilă de culoare {label!r}")


def _tbody(html: str) -> str:
    return html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]


def test_colour_counts_cover_every_row_and_always_mention_grey():
    html = _page(ColorStubDB(findings=_rows()))
    assert _pill(html, "Acum") == "🔴 Acum 1"
    assert _pill(html, "Curând") == "🟡 Curând 1"
    assert _pill(html, "Nedecis") == "⚪ Nedecis 2"
    assert _pill(html, "Ciclul obișnuit") == "🟢 Ciclul obișnuit / De urmărit* 3"


def test_a_pill_and_the_rows_it_brings_call_the_state_by_the_same_word():
    """The operator read "fără date" on the dashboard card, "gri" on the pill and "Nedecis" on
    the row: three words for one state across two clicks. The pill must carry the very label
    its rows carry (green carries both of its decisions' labels), with the colour word and the
    CISA name only in the tooltip."""
    html = _page(ColorStubDB(findings=_rows()))
    body = _tbody(html)
    for emoji, pill_label in (("🔴", "Acum"), ("🟡", "Curând"), ("⚪", "Nedecis"),
                              ("🟢", "Ciclul obișnuit / De urmărit*")):
        assert _pill(html, pill_label).startswith(f"{emoji} {pill_label} ")
        for word in pill_label.split(" / "):
            assert f"{emoji} {word}" in body, (pill_label, word)
    # The colour word is the filter's argument, not the state's name: it must not be the
    # visible text of any pill any more.
    visible = [m.group(1) for m in re.finditer(
        r'<a href="[^"]+" class="pill[^"]*"[^>]*>([^<]*)</a>', html)]
    assert not any(re.search(r"\b(roșu|galben|gri|verde)\b", t) for t in visible), visible
    assert 'title="gri · nu se poate decide: lipsesc date"' in html
    assert 'title="roșu · decizia CISA SSVC: Act"' in html


def test_grey_shows_even_with_zero_rows():
    """"Nothing without data" is a fact the operator should be able to read, not
    an absence he has to notice."""
    rows = [r for r in _rows() if r["risk_color"] != "grey"]
    html = _page(ColorStubDB(findings=rows))
    assert _pill(html, "Nedecis") == "⚪ Nedecis 0"


def test_selecting_a_colour_shows_only_that_colour_and_keeps_the_other_counts():
    html = _page(ColorStubDB(findings=_rows()), "/findings?culoare=grey")
    body = _tbody(html)
    assert body.count("<tr") == 2, "filtrul pe gri a arătat alte rânduri"
    assert "CVE-2026-1002" in body and "CVE-2026-1003" in body
    # The other three pills still say what is behind them; counted after the
    # colour filter they would all read zero and the page would look empty.
    assert _pill(html, "Acum") == "🔴 Acum 1"
    assert _pill(html, "Ciclul obișnuit") == "🟢 Ciclul obișnuit / De urmărit* 3"
    assert 'aria-current="page"' in html


def test_an_unknown_colour_is_reported_and_shows_everything():
    html = _page(ColorStubDB(findings=_rows()), "/findings?culoare=purple")
    assert "Culoare necunoscută" in html and "purple" in html
    assert _tbody(html).count("<tr") == 7, "o culoare inventată a golit pagina"


def test_a_grey_row_says_no_data_and_why_never_a_green_label():
    html = _page(ColorStubDB(findings=_rows()))
    body = _tbody(html)
    grey_row = [r for r in body.split("<tr") if "CVE-2026-1002" in r][0]
    assert "⚪ Nedecis" in grey_row
    risk_cell = grey_row.split("<td")[1]
    assert "🟢" not in risk_cell and "Ciclul obișnuit" not in risk_cell, (
        "un rând fără date poartă o decizie sau o culoare verde")
    # Celula spune doar ce lipsește; fraza lungă și capetele posibile sunt în `title`.
    tag, _, visible = risk_cell.partition(">")
    assert "fără EPSS" in visible and "ar putea fi" not in visible, visible
    assert "ar putea fi între Track și Attend" in tag, "explicația lungă nu mai e nicăieri"
    assert "lipsește EPSS (nu există încă pentru acest CVE)" in tag


def test_the_colour_labels_lead_with_what_to_do_and_keep_the_ssvc_name_in_the_tooltip():
    body = _tbody(_page(ColorStubDB(findings=_rows())))
    assert "🔴 Acum" in body
    assert "🟡 Curând" in body
    assert "🟢 Ciclul obișnuit" in body
    assert "🟢 De urmărit*" in body
    assert "Attend — accelerat" not in body and "Act — acum" not in body
    # The CISA name stays reachable from the row (the cell's `title`), and from the
    # legend above the table, so a label can still be looked up in the published tree.
    amber_row = [r for r in body.split("<tr") if "CVE-2026-1001" in r][0]
    assert "Decizie CISA SSVC: Attend" in amber_row


def test_a_pending_reboot_is_marked_on_the_row():
    body = _tbody(_page(ColorStubDB(findings=_rows())))
    amber_row = [r for r in body.split("<tr") if "CVE-2026-1001" in r][0]
    assert "🔁" in amber_row


def test_the_page_states_the_assumption_it_made_about_the_mission():
    """Every finding is evaluated as Mission = medium: the single most
    consequential input of the tree (measured: 4 non-green findings at medium,
    277 at high). The page must not let that stay implicit."""
    html = _page(ColorStubDB(findings=_rows()))
    assert "Presupunere" in html and "medie" in html
    # The state's name comes from the label source, not from this file: a rename there that
    # leaves the sentence in the template behind must fail here, not read fine on the page.
    assert f"{rv.COLOR_EMOJI['grey']} {rv.DECISION_LABEL_RO[None]} înseamnă că lipsesc date" in html
    assert "Gri înseamnă" not in html, "the legend went back to a second name for the state"


def test_the_page_legend_is_the_generated_one_and_not_a_hand_typed_copy():
    """The legend on the server's findings page is the only place an operator reading the
    table learns what a state's name is in CISA's tree. Typed by hand into the template (round
    1 of this change did exactly that on the Telegram list) it said "🟢 De urmărit (Track)" —
    the name of Track* attached to Track — and nothing failed: no test rendered this page and
    read the legend. Rendered here through the real router, the page must carry, character
    for character, the text `risk_view.legend_states()` builds from the very labels the rows
    print."""
    html = _page(ColorStubDB(findings=_rows()))
    assert rv.legend_states() in html, "the page legend is not the generated one"
    assert "De urmărit (Track)" not in html, "Track* name attached to Track again"
    # The pairing itself, read from the label tables and not from the generator under test.
    for decision in (ssvc.ACT, ssvc.ATTEND, ssvc.TRACK, ssvc.TRACK_STAR):
        pair = (f"{rv.COLOR_EMOJI[ssvc.COLOR_OF[decision]]} {rv.DECISION_LABEL_RO[decision]} "
                f"({rv.DECISION_SSVC_NAME[decision]})")
        assert pair in html, pair


def test_the_prose_around_the_legend_uses_the_label_of_the_state_it_talks_about():
    """The sentence after the legend explains that Track* is the ordinary cycle watched more
    closely. It names the state in a literal inside the template: if "De urmărit*" is renamed
    in the label source the legend follows (it is generated) and this sentence would go on
    naming a state that no row carries."""
    html = " ".join(_page(ColorStubDB(findings=_rows())).split())
    star = rv.DECISION_LABEL_RO[ssvc.TRACK_STAR]
    plain = rv.DECISION_LABEL_RO[ssvc.TRACK].lower()
    assert f"„{star}” e {plain}, dar cu o privire mai deasă" in html


def test_the_legend_says_every_cause_of_a_kev_does_not_know():
    """The cell says "nu se știe" for a row whose KEV list could not be read, with no CVE,
    whose assessment crashed, or that was never evaluated. A legend naming two of the four
    makes the other two read as a fault."""
    html = " ".join(_page(ColorStubDB(findings=_rows())).split())
    for cause in ("lista KEV n-a putut fi citită", "rândul n-are CVE",
                  "evaluarea lui s-a oprit cu o eroare", "încă n-a fost făcută"):
        assert cause in html, cause


def test_a_hostile_risk_value_is_text_not_markup():
    row = _finding(id=1, risk_color="grey", risk_decision=None,
                   risk={"decision": None, "missing": ['<img src=x onerror=alert(1)>'],
                         "possible": ["<script>", "track"]})
    html = _page(ColorStubDB(findings=[row]))
    assert "<img src=x" not in html and "<script>alert" not in html
    assert "&lt;img" in html


def test_a_row_that_was_never_assessed_is_grey_with_the_default_priority():
    html = _page(ColorStubDB(findings=[_finding(id=1, risk={}, risk_color="grey")]))
    body = _tbody(html)
    assert "⚪ Nedecis" in body and "încă neevaluată" in body


def test_a_colour_the_vocabulary_does_not_know_is_drawn_grey():
    """Same rule as the aggregator's `toColor`: unknown means grey, not green."""
    html = _page(ColorStubDB(findings=[_finding(id=1, risk_color="purple")]))
    assert "⚪ Nedecis" in _tbody(html)


def test_the_page_urls_carry_the_colour_filter():
    assert findings_router.page_url(None, 1, "red") == "/findings?culoare=red"
    assert findings_router.page_url("os", 3, "grey") == "/findings?asociat=os&culoare=grey&pagina=3"
    assert findings_router.page_url(None, 1) == "/findings"


def test_a_category_pill_keeps_the_selected_colour():
    """Pressing "sistem" while looking at the reds must not drop the operator
    into a different list."""
    html = _page(ColorStubDB(findings=_rows()), "/findings?culoare=red")
    links = [html_mod.unescape(m.group(1))
             for m in re.finditer(r'<a href="([^"]+asociat=[^"]+)"', html)]
    assert links, "nicio pastilă de categorie în pagină"
    for link in links:
        assert "culoare=red" in link, link


def test_an_overlay_row_is_labelled_as_sentinels_rule_in_the_panel_and_the_page_says_so():
    """The server's own panel: the 🟡 the tree did not give carries Sentinel's name
    in the label and the reason, the row's tooltip carries the full sentence, and
    the page note names the exception. A neighbouring ordinary Attend is untouched."""
    overlay = {
        "decision": "attend",
        "points": {"exploitation": {"value": "none", "basis": "vulnrichment",
                                    "as_of": "2025-04-08"}},
        "epss": {"p": 0.99225},
        "overlay": {"basis": "epss_overlay", "floor": "attend", "ssvc_decision": "track",
                    "epss": 0.99225, "observation_as_of": "2025-04-08",
                    "observation_age_days": 542, "min_epss": 0.5, "min_age_days": 180}}
    ordinary = {"decision": "attend",
                "points": {"exploitation": {"value": "active", "basis": "kev"}}}
    rows = [_finding(id=1, package="p1", priority=77, risk_color="amber",
                     risk_decision="attend", cve="CVE-2026-2001", risk=overlay),
            _finding(id=2, package="p2", priority=60, risk_color="amber",
                     risk_decision="attend", cve="CVE-2026-2002", risk=ordinary)]
    html = _page(ColorStubDB(findings=rows))
    body = _tbody(html)
    lifted = [r for r in body.split("<tr") if "CVE-2026-2001" in r][0]
    plain = [r for r in body.split("<tr") if "CVE-2026-2002" in r][0]
    assert "🟡 Curând · regula Sentinel" in lifted
    assert "EPSS 99,2%, CISA veche" in lifted
    assert "REGULI A SENTINEL" in lifted, "the tooltip lost the explanation"
    assert "Sentinel" not in plain
    assert "Singura excepție, a Sentinel și nu a SSVC" in html


def _headers(html: str) -> list[str]:
    head = html.split("<thead>", 1)[1].split("</thead>", 1)[0]
    return re.findall(r"<th[^>]*>([^<]*)</th>", head)


def test_cvss_epss_and_kev_sit_side_by_side_under_those_names():
    """The operator could not find CVSS on the page: it sat under "Importanță", two columns
    from a KEV that was only a flame inside the severity cell. The three signals are read
    together, so they are adjacent and named for what they are."""
    headers = _headers(_page(ColorStubDB(findings=_rows())))
    at = headers.index("CVSS")
    assert headers[at:at + 3] == ["CVSS", "EPSS", "KEV"], headers
    assert "Importanță" not in headers


def test_every_cell_sits_under_the_header_that_names_it():
    """`_headers` comparisons prove the HEADERS agree between the two pages; they say nothing
    about the cells. A template that put EPSS under "CVSS" (headers untouched) passed the whole
    suite — and is the divergence that misleads: a probability read as a severity score. Each
    cell is read through the index of ITS header, with values that no other cell can share."""
    risk = {"decision": "act", "missing": [],
            "cvss": {"source": "redhat", "score": 7.5},
            "epss": {"p": 0.0045, "percentile": 0.3682},
            "points": {"exploitation": {"value": "active", "basis": "kev"}}}
    row = _finding(id=1, cve="CVE-2026-7777", severity="critical", package="pkg-seven",
                   fixed_version="9.9.9-fix", title="titlu-sapte", kev=True,
                   kev_due_date=datetime.date(2026, 10, 12), epss=0.0045,
                   epss_percentile=0.3682, risk_color="red", risk_decision="act", risk=risk)
    html = _page(ColorStubDB(findings=[row]))
    headers = _headers(html)
    tr = [r for r in _tbody(html).split("<tr") if "CVE-2026-7777" in r][0]
    cells = [re.sub(r"<[^>]+>", "", c).strip()
             for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, flags=re.S)]
    # A row with more or fewer cells than headers shifts every cell after it.
    assert len(cells) == len(headers), (headers, cells)
    cell = dict(zip(headers, cells))
    assert "🔴 Acum" in cell["Risc"], cell
    assert "critical" in cell["Severitate"], cell
    assert "CVE-2026-7777" in cell["CVE"], cell
    assert cell["CVSS"] == "CVSS 7,5 (Red Hat)", cell
    assert cell["EPSS"] == "0,45% (percentila 37)", cell
    assert cell["KEV"] == "da — 2026-10-12", cell
    assert cell["Pachet"] == "pkg-seven", cell
    assert cell["Fix"] == "9.9.9-fix", cell
    # What the row is associated with moved from its own column to the title cell's second line.
    assert cell["Titlu"].startswith("titlu-sapte") and "Sistem de operare" in cell["Titlu"], cell


def test_the_table_stays_at_nine_columns_so_it_fits_a_1700px_screen():
    """The tenth column ("Asociat cu") pushed the table 484 px past the wrapper at 1700 px in
    Edge (measured, five rows with production-like values): the rightmost column was a scroll
    away, and a column the operator has to scroll to find is one they do not read. The
    association now sits under the title. A browser is not part of this suite, so this cannot
    measure the width — it holds the column count that WAS measured, and whoever adds a column
    has to re-measure at 1700 px (headless Edge, `--window-size=1700,1000`) and update this."""
    html = _page(ColorStubDB(findings=_rows()))
    headers = _headers(html)
    assert headers == ["Risc", "Severitate", "CVE", "CVSS", "EPSS", "KEV", "Pachet", "Fix",
                       "Titlu"], headers
    # Nothing was lost by dropping the column: every row still says what it is associated with.
    body = _tbody(html)
    assert body.count('class="muted small asociat"') == 7


def test_the_kev_cell_says_yes_with_the_due_date_no_or_that_it_does_not_know():
    """A "nu" for a row with no CVE, or whose KEV list could not be read, would reassure
    about exactly what nobody checked."""
    rows = [
        _finding(id=1, package="pkg-1", priority=90, cve="CVE-2026-3001", kev=True,
                 kev_due_date=datetime.date(2026, 10, 12), risk_color="red",
                 risk_decision="act", risk={"decision": "act", "missing": []}),
        _finding(id=2, package="pkg-2", priority=50, cve="CVE-2026-3002", kev=False,
                 risk_color="green", risk_decision="track",
                 risk={"decision": "track", "missing": []}),
        _finding(id=3, package="pkg-3", priority=45, cve="CVE-2026-3003", kev=False,
                 risk_color="grey", risk_decision=None,
                 risk={"decision": None, "missing": ["kev_mirror"]}),
        _finding(id=4, package="pkg-4", priority=44, cve=None, kev=False,
                 risk_color="grey", risk_decision=None,
                 risk={"decision": None, "missing": ["cve"]}),
    ]
    db = ColorStubDB(findings=rows)
    html = _page(db)
    body = _tbody(html)
    # The due date is only in the cell if the query selects it: the stub returns whatever
    # row it was given, so the SQL itself is checked, not just the rendering.
    assert any("f.kev_due_date" in sql for sql, _ in db.seen_sql), "list_open no longer selects kev_due_date"

    def kev_cell(marker: str) -> str:
        row = [r for r in body.split("<tr") if marker in r][0]
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, flags=re.S)
        return re.sub(r"<[^>]+>", "", cells[_headers(html).index("KEV")]).strip()

    assert kev_cell("pkg-1") == "da — 2026-10-12"
    assert kev_cell("pkg-2") == "nu"
    assert kev_cell("pkg-3") == "nu se știe"
    assert kev_cell("pkg-4") == "nu se știe"


def test_a_green_row_with_nothing_to_say_has_no_second_line_in_its_risk_cell():
    """"Track* — de urmărit · EPSS 0,24%": the second line repeated the EPSS column and told
    the reader nothing to act on. When there is no reason the cell is the label alone —
    no empty `<br>` either, which would still cost a line of height."""
    quiet = {"decision": "track", "missing": [], "epss": {"p": 0.0024}}
    loud = {"decision": "track", "missing": [], "epss": {"p": 0.9}}
    rows = [_finding(id=1, package="pkg-1", priority=10, cve="CVE-2026-4001", epss=0.0024,
                     risk_color="green", risk_decision="track", risk=quiet),
            _finding(id=2, package="pkg-2", priority=9, cve="CVE-2026-4002", epss=0.9,
                     risk_color="green", risk_decision="track", risk=loud)]
    body = _tbody(_page(ColorStubDB(findings=rows)))
    # The visible part of the cell, after its opening tag: the `title` legitimately
    # carries the EPSS (it is the full explanation).
    cell = lambda marker: [r for r in body.split("<tr") if marker in r][0].split(  # noqa: E731
        "</td>")[0].split("<td", 1)[1].partition(">")[2]
    assert "<br>" not in cell("pkg-1") and "EPSS 0,24%" not in cell("pkg-1")
    assert "EPSS 90,0%" in cell("pkg-2"), "a high EPSS beside a green is news and keeps its line"


def test_the_risk_cell_has_the_class_that_gives_it_a_width():
    """The ribbon came from a cell with no width of its own beside eight others. The class
    must be on the cell AND defined in the stylesheet that is actually served."""
    from pathlib import Path
    body = _tbody(_page(ColorStubDB(findings=_rows())))
    assert body.count('<td class="risc"') == 7
    # One colour marker, not two: the label already starts with the emoji (the same one Telegram
    # and the aggregator draw), and a CSS dot beside it read "● 🟡 Curând" — the same fact
    # twice, for 16 px of a column the table has no width to spare for.
    assert body.count('<strong class="risc-eticheta">') == 7
    for cell in re.findall(r'<td class="risc"[^>]*>(.*?)</td>', body, re.S):
        assert 'class="dot' not in cell, cell
        assert re.match(r'<strong class="risc-eticheta">(🔴|🟡|🟢|⚪) \S', cell), cell
    # Positive control: the dot is gone from the Risc cell, not from the page — the severity
    # column keeps its own (a different fact: how bad, not what to do).
    assert body.count('<td><span class="dot dot-') == 7
    css = (Path(findings_router.__file__).parent.parent / "static" / "css"
           / "sentinel.css").read_text(encoding="utf-8")
    assert re.search(r"td\.risc\s*\{[^}]*min-width", css), "the class has no width"
    assert re.search(r"\.risc-eticheta\s*\{[^}]*white-space:\s*nowrap", css)


def test_the_title_has_a_floor_and_cvss_and_epss_may_wrap_so_the_title_is_not_what_gives():
    """With eight columns that never wrap the title was the remainder: 173-194 px at 1700 px
    (Edge, rows with production-shaped titles), so a 62-character title took three lines and
    a 142-character one seven (a row of 213-260 px) — and on production 59% of the 821 open
    titles are over 60 characters. The title now has a floor, and CVSS and EPSS (not "nowrap"
    any more) give the width back by breaking between words, each with a width of its own below
    which the table layout does not push it (without it "(percentila 37)" goes to three
    lines). KEV stays unbroken on purpose: "da — 2026-10-12" wrapped at the hyphens of the date
    ("2026-" / "10-12", seen in Edge). The class names must be on the cells AND defined in the
    served stylesheet, and `nowrap` must be off the two that give. A browser is not part of this
    suite: the pixel figures are in the comment above these rules; whoever changes a column
    re-measures at 1700 px and 1366 px (headless Edge, `--window-size`)."""
    from pathlib import Path
    body = _tbody(_page(ColorStubDB(findings=_rows())))
    assert body.count('<td class="titlu">') == 7
    for cls in ("cvss", "epss"):
        assert body.count(f'<td class="small {cls}">') == 7, cls
    assert body.count('<td class="small nowrap">') == 7, "the KEV cell is no longer unbroken"
    css = (Path(findings_router.__file__).parent.parent / "static" / "css"
           / "sentinel.css").read_text(encoding="utf-8")
    floor = re.search(r"table\.findings td\.titlu\s*\{[^}]*min-width:\s*([\d.]+)rem", css)
    assert floor, "the title has no floor in the stylesheet"
    assert float(floor.group(1)) >= 14, "a floor that low is the squeezed title again"
    for cls in ("cvss", "epss"):
        rule = re.search(rf"table\.findings td\.{cls}\s*\{{([^}}]*)\}}", css)
        assert rule and "min-width" in rule.group(1), f"{cls} has no width of its own"
        assert "nowrap" not in rule.group(1), f"{cls} cannot wrap and so cannot give"
    # EPSS must hold "(percentila 37)" on one line: below ~7.5rem it takes three lines and the
    # row gets taller than the title it was meant to make room for.
    epss = float(re.search(r"td\.epss\s*\{[^}]*min-width:\s*([\d.]+)rem", css).group(1))
    assert epss >= 7.5, epss


# --- Fix and Pachet: whole identifiers, a width the longest cell does not dictate -------------

#: The worst `fixed_version` among the 648 open findings on the production host (5 Oct 2026,
#: symfony/mime): 135 characters, 19 comma-separated versions. Ten rows of 648 are over 60.
WORST_FIX = ("3.0.0, 5.0.0, 6.3.0, 6.4.0, 7.1.0, 7.3.0, 7.4.12, 6.2.0, 5.1.0, 5.4.52, 6.1.0, "
             "7.4.0, 8.0.12, 4.0.0, 5.2.0, 5.3.0, 5.4.0, 6.4.40, 7.2.0")

_SPAN = re.compile(r'<span class="nowrap">(.*?)</span>', re.S)


def _cell_of(html: str, cve: str, cls: str) -> str:
    """The inside of the `<td class="{cls}">` of the one row whose CVE is `cve`."""
    rows = [r for r in _tbody(html).split("<tr") if cve in r]
    assert len(rows) == 1, f"{cve} apare în {len(rows)} rânduri"
    m = re.search(rf'<td class="{cls}">(.*?)</td>', rows[0], re.S)
    assert m, f"rândul {cve} n-are celula {cls!r}"
    return m.group(1)


def _page_of(**per_row) -> str:
    """One page whose rows carry the given `fixed_version`/`package` lists, CVE-2026-7000 on."""
    n = max(len(v) for v in per_row.values())
    rows = []
    for i in range(n):
        over = {k: v[i] for k, v in per_row.items() if i < len(v)}
        rows.append(_finding(id=i + 1, priority=90 - i, cve=f"CVE-2026-{7000 + i}",
                             **{"package": f"pkg-{i + 1}", **over}))
    return _page(ColorStubDB(findings=rows))


def test_the_fix_cell_wraps_between_versions_and_never_inside_one():
    """THE OPERATOR LOSES THE TITLE. `nowrap` on the whole Fix cell made the column as wide as
    its widest value, and on production ten rows of 648 have a `fixed_version` over 60
    characters (the worst: 135, nineteen versions) — so those ten set the width for all of
    them: 775 px for Fix, the table scrolled 650 px at 1700 px, and the title, the only column
    that says WHAT the vulnerability is, was entirely off-screen. The cell must break between
    versions, and a version broken at its hyphen ("15.6.0-" / "canary.60") reads wrong, so each
    version is its own unbreakable span and ", " is the only place a line may end. The text
    the operator reads must be exactly what the scanner stored."""
    html = _page_of(fixed_version=[
        WORST_FIX,                        # production's worst
        "15.6.0-canary.60, 16.0.10",      # hyphens inside a version
        "2",                              # one version, no separator
        "1.0,2.0",                        # separator without a space
        "<b>1</b>, 2",                    # markup in a version must stay inert
        None, "", " , ,"])                # nothing to show: a dash, not an empty cell
    expected = {
        "CVE-2026-7000": WORST_FIX.split(", "),
        "CVE-2026-7001": ["15.6.0-canary.60", "16.0.10"],
        "CVE-2026-7002": ["2"],
        "CVE-2026-7003": ["1.0", "2.0"],
        "CVE-2026-7004": ["&lt;b&gt;1&lt;/b&gt;", "2"],
    }
    assert len(expected["CVE-2026-7000"]) == 19
    for cve, versions in expected.items():
        cell = _cell_of(html, cve, "mono fix")
        assert _SPAN.findall(cell) == versions, (cve, cell)
        # Between the spans there is ", " and nothing else: the comma stays glued to its
        # version, the space after it is the one place the line can end.
        assert _SPAN.sub("\x00", cell) == ", ".join("\x00" for _ in versions), (cve, cell)
    assert "<b>" not in _tbody(html), "a version became live markup"
    for cve in ("CVE-2026-7005", "CVE-2026-7006", "CVE-2026-7007"):
        assert _cell_of(html, cve, "mono fix") == "—", cve


def test_the_fix_column_has_a_floor_and_a_ceiling_and_cannot_refuse_to_wrap():
    """THE TITLE IS PUSHED OFF-SCREEN AGAIN. The spans only help if the cell itself may wrap:
    `nowrap` back on the `<td>` is the old defect, and so is a column with no ceiling — on a
    wide screen the table hands out surplus width in proportion to what each column could use
    on one line, so Fix took 545-667 px of 2530 and left the title 509-592 (measured in Edge;
    with the ceiling, Fix 335-360 and the title 713-754). The floor keeps a column of short
    versions from falling to one version per line. A browser is not part of this suite: the
    pixel figures are in the comment above the rule."""
    from pathlib import Path
    html = _page_of(fixed_version=[WORST_FIX])
    assert '<td class="mono nowrap">' not in html, "the whole Fix cell is unbreakable again"
    assert _tbody(html).count('<td class="mono fix">') == 1
    css = (Path(findings_router.__file__).parent.parent / "static" / "css"
           / "sentinel.css").read_text(encoding="utf-8")
    rule = re.search(r"table\.findings td\.fix\s*\{([^}]*)\}", css)
    assert rule, "the Fix column has no rule in the stylesheet"
    body = rule.group(1)
    assert "white-space" not in body, "the Fix cell is told not to wrap"
    floor = re.search(r"min-width:\s*([\d.]+)rem", body)
    ceiling = re.search(r"max-width:\s*([\d.]+)rem", body)
    assert floor and ceiling, "Fix needs both a floor and a ceiling"
    assert 8 <= float(floor.group(1)) < float(ceiling.group(1)) <= 28, (floor.group(1), ceiling.group(1))
    # The spans lean on this utility class being exactly "do not break".
    assert re.search(r"\.nowrap\s*\{[^}]*white-space:\s*nowrap", css)


def test_the_package_cell_never_breaks_a_name_at_its_hyphen():
    """THE OPERATOR READS A WRONG PACKAGE NAME. Measured on the production rows: with the table
    squeezed, "symfony/http-foundation" was drawn "symfony/http-" over "foundation" — the same
    reading error as a version cut at its hyphen. `nowrap` on the cell would let the longest
    name set the width for everyone, so each "/"-separated part is an unbreakable span and a
    `<wbr>` between parts is the only place the name may break."""
    html = _page_of(package=["symfony/http-foundation", "mtdowling/jmespath.php",
                             "openssl-libs", "@t/node/<img src=x onerror=1>", None, ""])
    expect = {
        "CVE-2026-7000": ["symfony/", "http-foundation"],
        "CVE-2026-7001": ["mtdowling/", "jmespath.php"],
        "CVE-2026-7002": ["openssl-libs"],
        "CVE-2026-7003": ["@t/", "node/", "&lt;img src=x onerror=1&gt;"],
    }
    for cve, parts in expect.items():
        cell = _cell_of(html, cve, "mono pachet")
        assert _SPAN.findall(cell) == parts, (cve, cell)
        assert _SPAN.sub("\x00", cell) == "<wbr>".join("\x00" for _ in parts), (cve, cell)
    assert "<img" not in _tbody(html), "a package name became live markup"
    for cve in ("CVE-2026-7004", "CVE-2026-7005"):
        assert _cell_of(html, cve, "mono pachet") == "—", cve
