"""The aggregator's reports page uses the width it asks for, and keeps a source on one line.

What goes wrong for the operator if this fails. The page was inside the 72rem reading column; the
operator asked for it full width. Measured (Edge, Segoe UI, viewport 1700, the 48 completed hours
of production on 6 Oct 2026 — numbers in the comment above `.din-ce` in `panel.css`):

* with the sources of an hour stacked one under another, the table needed only 582 px and was
  already 1112 px wide at 72rem: width was never what the page lacked, HEIGHT was (rows of 107 px,
  a 5173 px page for 48 hours). Giving that layout `wide` alone would only have stretched 582 px of
  content over 1560 px;
* with the sources side by side the table needs 1039 px, rows are 40 px and the page 1933 px, and
  `wide` finally has something to do: 72rem leaves 73 px of margin, 100rem leaves 521.

This reads the stylesheet as TEXT, so it runs in a fresh clone with no node. The markup half (the
page asks for `wide`, the sources are siblings in one `.din-ce`, no other page asks for it) is
`aggregator/tests/ai-panel.test.ts`. The pixel widths are MEASUREMENTS in the CSS comment: a test
cannot measure them, and one that pretended to would be measuring its own intention.
"""

from __future__ import annotations

import re
from pathlib import Path

CSS = Path(__file__).resolve().parents[2] / "aggregator" / "public" / "panel.css"


def _rule(selector: str) -> dict[str, str]:
    css = re.sub(r"/[*].*?[*]/", "", CSS.read_text(encoding="utf-8"), flags=re.S)
    for m in re.finditer(r"([^{}]+)[{]([^{}]*)[}]", css):
        if " ".join(m.group(1).split()) == selector:
            return {k.strip(): " ".join(v.split()) for k, _, v in
                    (d.partition(":") for d in m.group(2).split(";")) if k.strip()}
    raise AssertionError(f"no rule {selector!r} in panel.css")


def test_wide_is_still_the_findings_width_so_the_two_wide_pages_share_a_left_edge():
    """Eșecul pe care îl previne: Rapoarte primește o lățime proprie (88rem, 96rem...) și trecerea
    dintre fila de vulnerabilități și cea de rapoarte mută marginea conținutului."""
    assert _rule("main.wide")["max-width"] == "100rem"


def test_the_sources_of_an_hour_sit_in_a_wrapping_row_not_a_stack():
    """Eșecul pe care îl previne: sursele revin una sub alta (107 px pe rând, 5173 px de pagină)."""
    row = _rule(".din-ce")
    assert row["display"] == "flex" and row["flex-wrap"] == "wrap", row


def test_a_source_label_is_never_broken_in_the_middle():
    """`auditd/audit_config_change 172` must wrap BETWEEN sources, not inside one.

    Eșecul pe care îl previne: o sursă ruptă la `/` sau între etichetă și număr — „auditd/" pe un
    rând și „audit_config_change 172" pe următorul se citesc ca două surse.
    """
    assert _rule(".din-ce .sursa")["white-space"] == "nowrap"
