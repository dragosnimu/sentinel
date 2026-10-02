"""The SSVC tree in `sentinel/scan/ssvc.py` is the published CISA tree, not ours.

The colour an operator sees comes straight out of this table. A row edited by
hand, or a copy that drifted, repaints findings without anyone having decided to.
`tests/fixtures/ssvc/cisa_coordinator_2_0_3.csv` is a verbatim copy of
`data/csv/cisa/cisa_coordinator_2_0_3.csv` from github.com/CERTCC/SSVC (last
changed in commit c5be80f18, 27 Aug 2025,
fetched 2 Oct 2026).
"""

from __future__ import annotations

import csv
from itertools import product
from pathlib import Path

import pytest

from sentinel.scan import ssvc

FIXTURE = Path(__file__).parent.parent / "fixtures" / "ssvc" / "cisa_coordinator_2_0_3.csv"

_PUBLISHED_WORD = {"track": ssvc.TRACK, "track*": ssvc.TRACK_STAR,
                   "attend": ssvc.ATTEND, "act": ssvc.ACT}


def _published() -> dict[tuple[str, str, str, str], str]:
    out = {}
    with FIXTURE.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            e = row["Exploitation v1.1.0"].replace("public poc", "poc")
            a = row["Automatable v2.0.0"]
            ti = row["Technical Impact v1.0.0"]
            m = row["Mission and Well-Being Impact v1.0.0"]
            out[(e, a, ti, m)] = _PUBLISHED_WORD[row["CISA Levels v1.1.0 (cisa)"]]
    return out


def test_the_fixture_is_the_whole_published_tree():
    """If the fixture were truncated or empty, every comparison below would pass
    over nothing and the operator's colours would be checked against no tree."""
    assert len(_published()) == 36


def test_every_row_of_the_published_tree_is_in_the_code_unchanged():
    """A row changed in `ssvc.py` without CISA having changed it paints findings
    red or green on our own authority while the page says "CISA SSVC"."""
    published = _published()
    assert ssvc.TABLE == published
    wrong = {k: (ssvc.decide(*k), v) for k, v in published.items()
             if ssvc.decide(*k) != v}
    assert wrong == {}


def test_the_vocabulary_covers_every_combination():
    """A combination missing from the table would raise in the middle of a scan
    the first time a finding landed on it."""
    for combo in product(ssvc.EXPLOITATION, ssvc.AUTOMATABLE,
                         ssvc.TECHNICAL_IMPACT, ssvc.MISSION):
        assert ssvc.decide(*combo) in ssvc.DECISIONS


@pytest.mark.parametrize("bad", [
    ("exploited", "yes", "total", "medium"),
    ("active", "maybe", "total", "medium"),
    ("active", "yes", "huge", "medium"),
    ("active", "yes", "total", "essential"),
])
def test_a_value_outside_the_vocabulary_is_an_error_not_a_track(bad):
    """A typo must not quietly become the lowest decision: the operator would
    read "green" about something nobody ever evaluated."""
    with pytest.raises(ValueError):
        ssvc.decide(*bad)
    with pytest.raises(ValueError):
        ssvc.decide_range(*bad)


def test_range_with_everything_known_is_the_decision():
    """With all four values known there is no uncertainty to report."""
    for combo, expected in _published().items():
        assert ssvc.decide_range(*combo) == (expected, expected)


def test_range_over_an_unknown_exploitation_spans_what_it_could_be():
    """The reason a finding with no EPSS is grey rather than green: with
    automatable+total+medium the answer is Track if nothing is exploited and Act
    if it is, and nobody knows which."""
    assert ssvc.decide_range(None, "yes", "total", "medium") == (ssvc.TRACK, ssvc.ACT)


def test_range_can_be_decided_despite_an_unknown_when_every_completion_agrees():
    """Not exploited-and-low-mission is Track whatever the CVSS says; the range
    must collapse, otherwise the grey would hide that an answer exists."""
    low, high = ssvc.decide_range("none", None, None, "low")
    assert low == high == ssvc.TRACK


def test_range_with_nothing_known_spans_the_whole_scale():
    assert ssvc.decide_range(None, None, None, None) == (ssvc.TRACK, ssvc.ACT)


def test_demote_goes_down_one_step_and_stops_at_track():
    """"The fix is installed, only a reboot is left" lowers the urgency by one
    step, never below the floor and never to a nonexistent level."""
    assert ssvc.demote(ssvc.ACT) == ssvc.ATTEND
    assert ssvc.demote(ssvc.ATTEND) == ssvc.TRACK_STAR
    assert ssvc.demote(ssvc.TRACK_STAR) == ssvc.TRACK
    assert ssvc.demote(ssvc.TRACK) == ssvc.TRACK


def test_colours_follow_the_decision_and_track_star_is_green():
    """CISA gives Track* the same remediation timeline as Track; if it were
    amber, a third of the page would turn amber for no change in what to do."""
    assert ssvc.COLOR_OF == {ssvc.ACT: "red", ssvc.ATTEND: "amber",
                             ssvc.TRACK_STAR: "green", ssvc.TRACK: "green"}
    assert set(ssvc.COLOR_OF) == set(ssvc.DECISIONS)


def test_the_decisions_are_ordered_from_least_to_most_urgent():
    """`demote` and the range both read the position in this tuple."""
    assert ssvc.DECISIONS == (ssvc.TRACK, ssvc.TRACK_STAR, ssvc.ATTEND, ssvc.ACT)
