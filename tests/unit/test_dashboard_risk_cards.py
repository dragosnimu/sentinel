"""The dashboard card and the report card carry the traffic light.

What goes wrong for the operator if they do not: a front page that says "812
vulnerabilities, none exploited" while one is red, or a card that stays quiet about
the findings nobody could evaluate and so looks cleanest exactly when least is known.
"""

from __future__ import annotations

from tests.unit.test_dashboard_render import _context, _env
from tests.unit.test_reports_page import _client, _kpi_cards, stub  # noqa: F401  (fixture)


LABEL = '<span class="kpi-label">Vulnerabilități</span>'


def _card(html: str) -> str:
    block = html.split(LABEL, 1)[1]
    return block.split('<span class="kpi-note">', 1)[1].split("</span>", 1)[0]


def _kpi(**over):
    base = {"evenimente_24h": 1, "ostile_24h": 1, "atacatori_24h": 1,
            "incidente_deschise": 0, "incidente_grave": 0, "vuln_deschise": 812,
            "vuln_kev": 0, "vuln_rosii": 0, "vuln_galbene": 0, "vuln_gri": 0, "blocate": 0}
    base.update(over)
    return base


def test_the_dashboard_card_says_red_amber_and_grey_and_always_the_grey():
    html = _env().get_template("dashboard.html").render(**_context(
        kpi=_kpi(vuln_rosii=1, vuln_galbene=3, vuln_gri=27, vuln_kev=2)))
    note = " ".join(_card(html).split())
    assert note == "1 roșii · 3 galbene · 27 fără date · 2 KEV", note


def test_grey_is_stated_even_when_it_is_zero():
    html = _env().get_template("dashboard.html").render(**_context(kpi=_kpi()))
    assert "0 fără date" in _card(html)


def test_the_dashboard_card_turns_bad_on_a_red_even_without_kev():
    """A CVE with EPSS 0.99 and no KEV entry used to leave this card calm."""
    red = _env().get_template("dashboard.html").render(**_context(kpi=_kpi(vuln_rosii=1)))
    calm = _env().get_template("dashboard.html").render(**_context(kpi=_kpi()))
    def card_class(html: str) -> str:
        # The card's own <div>, i.e. the last `kpi ` opener before its label (the
        # head div is `kpi-head`, with no space).
        return html.split(LABEL, 1)[0].rsplit('<div class="kpi ', 1)[1].split(">", 1)[0]
    assert "kpi-bad" in card_class(red), card_class(red)
    assert "kpi-bad" not in card_class(calm), card_class(calm)


def test_the_report_card_and_its_list_carry_the_colours(stub):  # noqa: F811
    with _client(stub) as c:
        body = c.get("/reports").text
    card = _kpi_cards(body)["Vulnerabilități deschise"]
    assert "1 roșii · 2 galbene" in " ".join(card.split())
    assert "1 fără date" in " ".join(card.split())
    # the stub row says kev=1 -> the card keeps saying KEV, next to the colours
    assert "1 KEV" in " ".join(card.split())
    assert "🔴 Roșii (Act)" in body and "🟡 Galbene (Attend)" in body
    assert "⚪ Fără date (gri)" in body
