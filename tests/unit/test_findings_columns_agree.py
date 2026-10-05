"""The two vulnerability tables read in the same order, under the same names.

The server console (`sentinel/web/templates/findings.html`) and the aggregator
(`aggregator/lib/panel-page.ts`) show the same findings to the same person. The operator
looked at them one after the other and could not find CVSS on either: it sat under
"Importanță", and KEV was a flame inside another cell on one page and a column on the
other. Two layouts for one list is how a reader learns to distrust both.

This reads the two SOURCE files as text, so it needs neither `node` nor
`aggregator/node_modules` and runs in a fresh clone: the "skipped without node" outcome
is exactly how an agreement test goes unrun for months.

What goes wrong for the operator if it fails: CVSS, EPSS and KEV drift apart again (or
one page renames a column), and the two surfaces stop reading the same way.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "sentinel" / "web" / "templates" / "findings.html"
PANEL = REPO / "aggregator" / "lib" / "panel-page.ts"

#: The columns the two tables are required to share, in this order: the signals first
#: (risk, severity, CVE, CVSS, EPSS, KEV), then what identifies the row. Columns only one
#: surface has (the server's "Titlu" and "Asociat cu", the aggregator's "Stare") sit
#: after them without breaking the order.
SHARED = ["Risc", "Severitate", "CVE", "CVSS", "EPSS", "KEV", "Pachet", "Fix"]


def _server_headers() -> list[str]:
    html = TEMPLATE.read_text(encoding="utf-8")
    head = html.split("<thead>", 1)[1].split("</thead>", 1)[0]
    return re.findall(r"<th[^>]*>([^<]*)</th>", head)


def _aggregator_headers() -> list[str]:
    src = PANEL.read_text(encoding="utf-8")
    start = src.index("export function findingsPage")
    # The header literal is the concatenation of the `<th>...</th>` strings that open
    # the `table(` call; read it as text, whatever the quoting or the line breaks.
    body = src[start:]
    table_at = body.index("table(")
    headers = re.findall(r"<th[^>]*>([^<]*)</th>", body[table_at:body.index("view.findings.map")])
    return headers


def test_the_two_tables_share_their_columns_in_the_same_order():
    server, aggregator = _server_headers(), _aggregator_headers()
    # Positive controls: an empty read would make every comparison below vacuous.
    assert len(server) >= 8 and len(aggregator) >= 8, (server, aggregator)
    assert [h for h in server if h in SHARED] == SHARED, server
    assert [h for h in aggregator if h in SHARED] == SHARED, aggregator


def test_cvss_epss_and_kev_are_adjacent_on_both_surfaces():
    for name, headers in (("server", _server_headers()), ("aggregator", _aggregator_headers())):
        at = headers.index("CVSS")
        assert headers[at:at + 3] == ["CVSS", "EPSS", "KEV"], (name, headers)
        assert "Importanță" not in headers, (name, headers)
