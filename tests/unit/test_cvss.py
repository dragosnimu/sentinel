"""CVSS vectors: what Sentinel reads from them, and what it refuses to guess.

Three decisions of the traffic light hang on this module: the numeric score of
a vector that arrives without one (OSV), Automatable and Technical Impact. A
wrong reading here is a wrong colour with no error anywhere, so each rule is
pinned against the specification's own examples and against vectors measured on
the production host.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from sentinel.scan import cvss

PAIRS = Path(__file__).parent.parent / "fixtures" / "cvss_measured_pairs.csv"

# (vector, score the scanner paired with it) that do NOT agree with the
# specification's formula. Measured on production, 2 Oct 2026. Four are Ubuntu
# kernel CVEs (`linux-libc-dev`): one generic vector, `AV:L/AC:H/PR:L/...`,
# carries four different scores (6.4, 7.1, 7.8, 8.7) while the formula gives
# 7.0 for it, so the scanner paired a score from one assessment with a vector
# from another. The fifth is a GitHub advisory scoring 9.1 for a vector the
# formula puts at 9.0. They are listed instead of skipped: any NEW disagreement
# is a defect in `base_score` or in the data, and either deserves a look.
KNOWN_SOURCE_DISAGREEMENTS = {
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "6.4"),
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "7.1"),
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "7.8"),
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "8.7"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", "9.1"),
}

_FULL_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.mark.parametrize("vector,score", [
    (_FULL_V3, 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    # The pair Red Hat publishes for CVE-2024-6501 (the example in the brief).
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L", 3.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
])
def test_base_score_matches_the_specification_examples(vector, score):
    """OSV returns a vector where a score belongs. If this arithmetic is off,
    every finding scored from an OSV vector carries a wrong "importance"."""
    assert cvss.base_score(cvss.parse(vector)) == score


def test_the_fixture_holds_the_measured_pairs():
    """An empty fixture would make the next test pass over nothing."""
    with PAIRS.open(encoding="utf-8", newline="") as fh:
        assert len(list(csv.DictReader(fh))) >= 70


def test_base_score_agrees_with_every_pair_measured_on_production():
    """All (vector, score) pairs trivy reported for open findings on the host:
    the calculator must reproduce each, except the disagreements named above
    (and those must still disagree, so the allowlist cannot go stale)."""
    disagree = set()
    with PAIRS.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            computed = cvss.base_score(cvss.parse(row["vector"]))
            if computed is None or abs(computed - float(row["score"])) > 1e-9:
                disagree.add((row["vector"], row["score"]))
    assert disagree == KNOWN_SOURCE_DISAGREEMENTS


def test_v4_has_no_computed_score():
    """The v4 score is a 270-entry lookup we do not carry. Returning a made-up
    number would be worse than returning none: the caller falls back to a
    severity estimate and says so."""
    vec = cvss.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert vec is not None and vec.version == "4.0"
    assert cvss.base_score(vec) is None


@pytest.mark.parametrize("value", [
    None, "", 42, b"CVSS:3.1/AV:N", [],
    "AV:N/AC:L/Au:N/C:P/I:P/A:P",                       # v2: not understood
    "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",         # missing A
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # value outside the spec
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:HH/I:H/A:H",
    "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicated metric
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/garbage",
    "CVSS:3.1",
    "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H",       # v4 without AT / S*
])
def test_what_is_not_a_whole_vector_is_unknown_not_a_guess(value):
    """A vector we cannot read must come out as "unknown" (grey on the page).
    A guessed `partial` or `no` would paint a colour nobody computed."""
    assert cvss.parse(value) is None
    assert cvss.automatable(cvss.parse(value)) is None
    assert cvss.technical_impact(cvss.parse(value)) is None
    assert cvss.base_score(cvss.parse(value)) is None


def test_temporal_and_environmental_extras_do_not_break_a_v3_vector():
    """Some feeds append `E:P/RL:O/RC:C`. They are not part of the base score."""
    vec = cvss.parse(_FULL_V3 + "/E:P/RL:O/RC:C")
    assert vec is not None
    assert cvss.base_score(vec) == 9.8


@pytest.mark.parametrize("flip", [
    "AV:N->AV:A", "AV:N->AV:L", "AC:L->AC:H", "PR:N->PR:L", "UI:N->UI:R",
])
def test_automatable_needs_all_four_conditions(flip):
    """Automatable is `yes` only for network + low complexity + no privileges +
    no user interaction. Relaxing any one of them would turn every local or
    interactive CVE into "an attacker can automate this" and Attend/Act."""
    old, new = flip.split("->")
    assert cvss.automatable(cvss.parse(_FULL_V3)) == "yes"
    assert cvss.automatable(cvss.parse(_FULL_V3.replace(old, new))) == "no"


def test_automatable_scope_and_impact_do_not_matter():
    """A network DoS with nothing but availability lost is still automatable;
    how bad it is belongs to Technical Impact."""
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert cvss.automatable(cvss.parse(v)) == "yes"


@pytest.mark.parametrize("c,i,a,expected", [
    ("H", "H", "H", "total"),     # code execution
    ("H", "H", "N", "total"),
    ("H", "N", "N", "partial"),   # full disclosure of the COMPONENT, not of the system
    ("H", "N", "H", "partial"),   # CVE-2024-53150 (C:H/I:N/A:H): `partial` at CISA
    ("H", "L", "H", "partial"),   # CVE-2025-39964 (C:H/I:L/A:H), measured on KEV
    ("N", "H", "N", "partial"),   # integrity alone is not control of everything
    ("L", "H", "N", "partial"),
    ("L", "L", "L", "partial"),   # neither is total
    ("L", "N", "N", "partial"),
    ("N", "L", "H", "partial"),
    ("N", "N", "H", "partial"),   # denial of service: limited control (CISA's own wording)
])
def test_technical_impact_is_total_only_when_confidentiality_and_integrity_are_both_high(
        c, i, a, expected):
    """SSVC's `total` is "total control over the behavior of the software, or total
    disclosure of all information ON THE SYSTEM". CVSS `C:H` is a total loss "within
    the impacted COMPONENT": a smaller thing, so reading `C:H` alone as `total`
    over-reads the vector. Measured on the host's 189 CVEs that have both a vector
    and a CISA value, `C:H and I:H` agrees with CISA on 179 (95%) and `C:H or I:H`
    on 149 (79%); 19 of the 20 CVEs with `C:H` and without `I:H` are `partial` at
    CISA. The `or` reading was tried first (the definition's wording suggested it)
    and it painted CVEs CISA calls partial as total, which can turn Track into
    Attend for a CVE CISA has not evaluated. Do not "fix" this back
    to `or` from the definition's text alone: the two scales differ in scope."""
    vec = cvss.parse(f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{c}/I:{i}/A:{a}")
    assert cvss.technical_impact(vec) == expected


_V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_v4_automatable_requires_no_attack_requirements():
    """`AT:P` means deployment conditions must hold: not reliably automatable.
    Measured: GHSA-2xp9-vwfh-vxw4 (a Next.js RCE) has AT:P and stays `no`."""
    assert cvss.automatable(cvss.parse(_V4)) == "yes"
    assert cvss.automatable(cvss.parse(_V4.replace("AT:N", "AT:P"))) == "no"


def test_v4_supplemental_automatable_is_the_answer_when_present():
    """CVSS v4's `AU` metric IS the SSVC decision point; when the publisher
    defined it, our heuristic must not overrule them."""
    assert cvss.automatable(cvss.parse(_V4 + "/AU:N")) == "no"
    assert cvss.automatable(cvss.parse(_V4.replace("AT:N", "AT:P") + "/AU:Y")) == "yes"
    # `X` means "not defined": fall back to the heuristic.
    assert cvss.automatable(cvss.parse(_V4 + "/AU:X")) == "yes"


def test_v4_technical_impact_reads_the_vulnerable_system_not_the_subsequent_one():
    """VC/VI are the component with the flaw; SC/SI are what it can reach next.
    SSVC's Technical Impact is "relative to the affected component"."""
    assert cvss.technical_impact(cvss.parse(_V4)) == "total"
    only_subsequent = _V4.replace("VC:H", "VC:N").replace("VI:H", "VI:N").replace("SC:N", "SC:H")
    assert cvss.technical_impact(cvss.parse(only_subsequent)) == "partial"


@pytest.mark.parametrize("vc,vi,expected", [
    ("H", "H", "total"), ("H", "N", "partial"), ("N", "H", "partial"),
    ("L", "L", "partial"), ("N", "N", "partial"),
])
def test_v4_technical_impact_is_total_only_when_both_vulnerable_system_axes_are_high(
        vc, vi, expected):
    """Same reading for v4 as for v3 (component, not system): VC:H alone is a total
    loss of the vulnerable system's confidentiality, not "all information on the
    system", so it is `partial` unless VI:H holds too. Reading it as `or` would carry
    the over-read measured on v3 into v4: a v4-only GHSA advisory with VC:H/VI:N
    coloured as if the whole system had been disclosed. (186 of the 189 measured
    pairs are v3. Of the 3 v4 pairs, the one with VC:H/VI:N, CVE-2026-46636, is
    `partial` at CISA: consistent with `and`, but one case is not a measurement.)"""
    v = _V4.replace("VC:H", f"VC:{vc}").replace("VI:H", f"VI:{vi}").replace("VA:H", "VA:N")
    assert cvss.technical_impact(cvss.parse(v)) == expected
