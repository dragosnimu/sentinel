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

import html as html_mod
import re
from collections import Counter

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
    for m in re.finditer(r'<a href="[^"]+" class="pill[^"]*"[^>]*>([^<]*)</a>', html):
        text = m.group(1).strip()
        if text.endswith(label):
            return text
    raise AssertionError(f"nicio pastilă de culoare {label!r}")


def _tbody(html: str) -> str:
    return html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]


def test_colour_counts_cover_every_row_and_always_mention_grey():
    html = _page(ColorStubDB(findings=_rows()))
    assert _pill(html, "roșu") == "🔴 1 roșu"
    assert _pill(html, "galben") == "🟡 1 galben"
    assert _pill(html, "gri") == "⚪ 2 gri"
    assert _pill(html, "verde") == "🟢 3 verde"


def test_grey_shows_even_with_zero_rows():
    """"Nothing without data" is a fact the operator should be able to read, not
    an absence he has to notice."""
    rows = [r for r in _rows() if r["risk_color"] != "grey"]
    html = _page(ColorStubDB(findings=rows))
    assert _pill(html, "gri") == "⚪ 0 gri"


def test_selecting_a_colour_shows_only_that_colour_and_keeps_the_other_counts():
    html = _page(ColorStubDB(findings=_rows()), "/findings?culoare=grey")
    body = _tbody(html)
    assert body.count("<tr") == 2, "filtrul pe gri a arătat alte rânduri"
    assert "CVE-2026-1002" in body and "CVE-2026-1003" in body
    # The other three pills still say what is behind them; counted after the
    # colour filter they would all read zero and the page would look empty.
    assert _pill(html, "roșu") == "🔴 1 roșu"
    assert _pill(html, "verde") == "🟢 3 verde"
    assert 'aria-current="page"' in html


def test_an_unknown_colour_is_reported_and_shows_everything():
    html = _page(ColorStubDB(findings=_rows()), "/findings?culoare=purple")
    assert "Culoare necunoscută" in html and "purple" in html
    assert _tbody(html).count("<tr") == 7, "o culoare inventată a golit pagina"


def test_a_grey_row_says_no_data_and_why_never_a_green_label():
    html = _page(ColorStubDB(findings=_rows()))
    body = _tbody(html)
    grey_row = [r for r in body.split("<tr") if "CVE-2026-1002" in r][0]
    assert "⚪ fără date" in grey_row
    assert "lipsește EPSS" in grey_row
    risk_cell = grey_row.split("<td")[1]
    assert "🟢" not in risk_cell and "Track —" not in risk_cell, (
        "un rând fără date poartă o decizie sau o culoare verde")


def test_the_colour_labels_are_the_ssvc_decisions():
    body = _tbody(_page(ColorStubDB(findings=_rows())))
    assert "🔴 Act — acum" in body
    assert "🟡 Attend — accelerat" in body
    assert "🟢 Track — ciclul obișnuit" in body
    assert "🟢 Track* — de urmărit" in body


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
    assert "Gri înseamnă că lipsesc date" in html


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
    assert "⚪ fără date" in body and "încă neevaluată" in body


def test_a_colour_the_vocabulary_does_not_know_is_drawn_grey():
    """Same rule as the aggregator's `toColor`: unknown means grey, not green."""
    html = _page(ColorStubDB(findings=[_finding(id=1, risk_color="purple")]))
    assert "⚪ fără date" in _tbody(html)


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
    assert "Attend — accelerat (regula Sentinel, nu SSVC)" in lifted
    assert "regula Sentinel (EPSS)" in lifted
    assert "REGULI A SENTINEL" in lifted, "the tooltip lost the explanation"
    assert "Sentinel" not in plain
    assert "Singura excepție, a Sentinel și nu a SSVC" in html
