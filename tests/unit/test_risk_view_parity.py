"""The traffic light reads the same on the server and on the aggregator.

`sentinel/scan/risk_view.py` writes the words the operator sees in Telegram and
in the server's own panel; `aggregator/lib/finding-risk.ts` writes them for the
external witness. Two implementations of one sentence are the way "🔴 Act" ends
up as "🟡" on one screen, or "0,13%" as "0,12%" (JavaScript's `toFixed` and
Python's `format` round the exact halves differently, which is why both use an
explicit half-up).

Runs the TypeScript functions through `node` on the same inputs and compares the
text byte for byte. Same convention as `test_aggregator_stream_columns.py`:
without `node` or `aggregator/node_modules` the test is SKIPPED with the reason —
"could not check" is not "agrees".
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from sentinel.scan import risk_view as rv

REPO = Path(__file__).resolve().parents[2]
AGGREGATOR = REPO / "aggregator"
NODE = shutil.which("node")

pytestmark = [
    pytest.mark.skipif(NODE is None, reason="node lipsește din PATH: paritatea Python/TypeScript "
                                            "NU s-a verificat (neverificat, nu „în regulă”)"),
    pytest.mark.skipif(not (AGGREGATOR / "node_modules").is_dir(),
                       reason="aggregator/node_modules lipsește: paritatea NU s-a verificat"),
]

EPSS_CASES = [
    (0.0045, 0.3682), (0.153, 0.92), (0.99225, 0.99936), (0.0005, None), (0.00004, None),
    (0.0, None), (1, None), (0.1225, None), (0.00125, None), ("0.0045", "0.3682"),
    (0.5, 0.5), (0.995, 0.995), (0.0099, 0.005), (0.0095, 0.115), (0.0001, 0.0),
    # Decimal ties that a binary `toFixed` rounds the other way: 0.145 -> 0.14,
    # 0.405 -> 0.40, 0.615 -> 0.61 in JavaScript, 0.15 / 0.41 / 0.62 half-up.
    (0.00145, None), (0.00405, 0.5), (0.00615, None), (0.00285, None), (0.00995, None),
    (None, None), ("garbage", None),
]
CVSS_CASES = [
    {"score": 3.1, "source": "redhat"}, {"score": 7.5, "source": "trivy"},
    {"score": 9.8, "source": "osv"}, {"score": 7.5, "source": "other"},
    {"score": None, "estimated": True}, {"score": None}, None,
]
RISK_CASES = [
    {},
    {"decision": None, "missing": ["epss"], "possible": ["track", "attend"]},
    {"decision": None, "missing": ["cvss"], "possible": ["track", "track"]},
    {"decision": None, "missing": ["cve", "kev_mirror"], "possible": ["track", "act"]},
    {"decision": None, "missing": ["epss_stale"]},
    {"decision": None, "missing": ["assessment_error"]},
    # The shape `risk._unassessable` really writes: the KEV cell must read "nu se știe" on
    # both ends (a crashed assessment keeps yesterday's `kev`, so "nu" would be a guess).
    {"v": 1, "missing": ["assessment_error"], "error": "KeyError: x"},
    {"decision": None, "missing": ["vulnrichment"], "possible": ["track", "attend"]},
    {"decision": None, "missing": ["exploitation_unpublished"], "possible": ["track", "track"]},
    {"decision": None},
    {"decision": "act", "points": {"exploitation": {"value": "active", "basis": "kev"}}},
    {"decision": "attend", "reboot_pending": True,
     "points": {"exploitation": {"value": "active", "basis": "kev"}}},
    {"decision": "attend", "epss": {"p": 0.92},
     "points": {"exploitation": {"value": "active", "basis": "epss"}}},
    {"decision": "track", "points": {"exploitation": {"value": "none", "basis": "epss"}}},
    {"decision": "act", "epss": {"p": 0.5},
     "points": {"exploitation": {"value": "active", "basis": "vulnrichment",
                                 "as_of": "2026-09-18"}}},
    {"decision": "attend", "reboot_pending": True, "epss": {"p": 0.5},
     "points": {"exploitation": {"value": "active", "basis": "vulnrichment"}}},
    {"decision": "track", "epss": {"p": 0.99225},
     "points": {"exploitation": {"value": "none", "basis": "vulnrichment",
                                 "as_of": "2025-04-08"}}},
    {"decision": "track", "points": {"exploitation": {"value": "none", "basis": "kev_absent"}}},
    # Sentinel's own overlay (EPSS beside an old CISA observation): the label must
    # be the same on both ends, and ignored when it is not the one deciding.
    {"decision": "attend", "epss": {"p": 0.99225},
     "points": {"exploitation": {"value": "none", "basis": "vulnrichment",
                                 "as_of": "2025-04-08"}},
     "overlay": {"basis": "epss_overlay", "floor": "attend", "ssvc_decision": "track",
                 "epss": 0.99225, "observation_as_of": "2025-04-08",
                 "observation_age_days": 542, "min_epss": 0.5, "min_age_days": 180}},
    {"decision": "attend", "reboot_pending": True, "epss": {"p": 0.6},
     "overlay": {"basis": "epss_overlay", "ssvc_decision": "track"}},
    {"decision": "attend", "overlay": {"basis": "something_else"}},
    {"decision": "attend", "overlay": "not a mapping"},
    # An overlay that cannot prove its observation is old: "nedatată", not "veche".
    {"decision": "attend", "epss": {"p": 0.9},
     "overlay": {"basis": "epss_overlay", "ssvc_decision": "track", "epss": 0.9,
                 "observation_as_of": None, "observation_age_days": None}},
    # The EPSS-only reason on a green is dropped below Sentinel's own threshold (0.5) and
    # kept from it upwards; on amber/red it is always kept. Cases on both sides of the edge.
    {"decision": "track", "epss": {"p": 0.4999}},
    {"decision": "track", "epss": {"p": 0.5}},
    {"decision": "track", "epss": {"p": 0.0024}},
    {"decision": "attend", "epss": {"p": 0.0024},
     "points": {"exploitation": {"value": "active", "basis": "epss"}}},
    # Grey codes: duplicates collapse, unknown codes stay visible, and a code that is also
    # a property of every JavaScript object must not turn into that property.
    {"decision": None, "missing": ["cve", "kev_mirror", "cve"], "possible": ["track", "act"]},
    {"decision": None, "missing": ["something_new"], "possible": ["track", "bogus"]},
    {"decision": None, "missing": ["constructor", "toString"],
     "possible": ["constructor", "track"]},
    {"decision": None, "missing": []},
]
KEV_CASES = [(True, "2026-10-12"), (True, None), (True, ""), (False, None)]
COUNT_CASES = [(1, 3, 27), (0, 0, 0), (12, 0, 5)]
COLORS = ["red", "amber", "green", "grey"]
DECISIONS = ["act", "attend", "track_star", "track", None]

BRIDGE = """
import {
  fmtEpss, fmtCvss, fmtKev, headline, greyReason, greyDetail, reasonLine, ssvcName,
  COLOR_STATE_RO, stateWithSsvc, pillTitle, legendStates, countsRo, KEV_UNKNOWN_NOTE_RO,
} from "../lib/finding-risk.ts";
const orNull = (r) => (Object.keys(r).length === 0 ? null : r);
const cases = JSON.parse(process.argv[2]);
const out = {
  epss: cases.epss.map(([p, pct]) => fmtEpss(p, pct)),
  cvss: cases.cvss.map((c) => fmtCvss(c)),
  headline: cases.headline.map(([c, d]) => headline(c, d)),
  headline_risk: cases.risk.flatMap((r) => cases.headline.map(([c, d]) => headline(c, d, orNull(r)))),
  grey: cases.risk.map((r) => greyReason(orNull(r))),
  grey_detail: cases.risk.map((r) => greyDetail(orNull(r))),
  reason: cases.risk.flatMap((r) => cases.colors.map((c) => reasonLine(c, orNull(r)))),
  kev: cases.risk.flatMap((r) => cases.kev.map(([k, due]) => fmtKev(k, due, orNull(r)))),
  ssvc: cases.decisions.map((d) => ssvcName(d)),
  vocab: {
    state: cases.colors.map((c) => COLOR_STATE_RO[c]),
    with_ssvc: cases.colors.map((c) => stateWithSsvc(c)),
    pill: cases.colors.map((c) => pillTitle(c)),
    legend: legendStates(),
    counts: cases.counts.map(([r, a, g]) => countsRo(r, a, g)),
    kev_note: KEV_UNKNOWN_NOTE_RO,
  },
};
process.stdout.write(JSON.stringify(out));
"""


def _typescript(cases: dict) -> dict:
    with tempfile.TemporaryDirectory(dir=AGGREGATOR, prefix=".tmp-risk-parity-") as tmp:
        script = Path(tmp) / "bridge.mjs"
        script.write_text(BRIDGE, encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [NODE, "--import", "tsx", str(script), json.dumps(cases)],
            cwd=AGGREGATOR, capture_output=True, text=True, encoding="utf-8",
            timeout=180, env={**os.environ, "NO_COLOR": "1"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def test_both_ends_write_the_same_words_for_the_same_inputs():
    cases = {
        "epss": EPSS_CASES, "cvss": CVSS_CASES, "risk": RISK_CASES, "colors": COLORS,
        "headline": [[c, d] for c in COLORS for d in DECISIONS],
        "kev": KEV_CASES, "decisions": DECISIONS + ["bogus", "constructor"],
        "counts": COUNT_CASES,
    }
    ts = _typescript(cases)

    py_epss = [rv.fmt_epss(p, pct) for p, pct in EPSS_CASES]
    assert ts["epss"] == py_epss, [
        (c, a, b) for c, a, b in zip(EPSS_CASES, ts["epss"], py_epss) if a != b]

    assert ts["cvss"] == [rv.fmt_cvss(c) for c in CVSS_CASES]
    assert ts["headline"] == [rv.headline(c, d) for c in COLORS for d in DECISIONS]
    assert ts["headline_risk"] == [rv.headline(c, d, r or None)
                                   for r in RISK_CASES for c in COLORS for d in DECISIONS]
    assert ts["grey"] == [rv.grey_reason(r or None) for r in RISK_CASES]
    assert ts["grey_detail"] == [rv.grey_detail(r or None) for r in RISK_CASES]
    py_reason = [rv.reason_line(c, r or None) for r in RISK_CASES for c in COLORS]
    assert ts["reason"] == py_reason, [
        (r, c, a, b) for (r, c), a, b in zip(
            [(r, c) for r in RISK_CASES for c in COLORS], ts["reason"], py_reason) if a != b]
    assert ts["kev"] == [rv.fmt_kev(k, due, r or None) for r in RISK_CASES
                         for k, due in KEV_CASES]
    assert ts["ssvc"] == [rv.ssvc_name(d) for d in DECISIONS + ["bogus", "constructor"]]
    # The state NAMES (one word per state on every screen), the legend built from them, the
    # pill tooltips, the count line and the KEV "does not know" sentence: the same text.
    vocab = ts["vocab"]
    assert vocab["state"] == [rv.COLOR_STATE_RO[c] for c in COLORS]
    assert vocab["with_ssvc"] == [rv.state_with_ssvc(c) for c in COLORS]
    assert vocab["pill"] == [rv.pill_title(c) for c in COLORS]
    assert vocab["legend"] == rv.legend_states()
    assert vocab["counts"] == [rv.counts_ro(*c) for c in COUNT_CASES]
    assert vocab["kev_note"] == rv.KEV_UNKNOWN_NOTE_RO
    assert vocab["counts"][0] == "Acum 1 · Curând 3 · Nedecis 27", vocab["counts"]
    # An empty comparison would pass for ever; these are the sizes we expect.
    assert len(ts["epss"]) == len(EPSS_CASES) >= 15
    assert len(ts["reason"]) == len(RISK_CASES) * len(COLORS)
    assert len(ts["kev"]) == len(RISK_CASES) * len(KEV_CASES)
    # ... and the interesting branches really reached the comparison, on BOTH sides: the
    # overlay (marker in the label, fact in the reason, "nedatată" when undated), a green
    # whose EPSS line was dropped and one that kept it, a grey code that collides with an
    # Object property, and the three KEV outcomes.
    assert any(rv.OVERLAY_TAG_RO in h for h in ts["headline_risk"])
    assert any(o == "EPSS 99,2%, CISA veche" for o in ts["reason"])
    assert any(o == "EPSS 90,0%, CISA nedatată" for o in ts["reason"])
    assert any(o is None for o in ts["reason"]) and any(o == "EPSS 50,0%" for o in ts["reason"])
    assert "constructor, toString" in ts["grey"]
    assert {"da — 2026-10-12", "da", "nu", "nu se știe"} <= set(ts["kev"])
