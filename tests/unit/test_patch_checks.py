"""`pkg_version` must actually compare versions — and compare the RIGHT parts.

S1: the runtime used to read `expect_version`, a key no validated plan can
contain (the validator requires `equals` or `at_least`), so the check reduced
to `rpm -q NAME` exits 0 — "is it installed at all", never "is it the version
the patch was supposed to land". A patch whose apply step silently failed to
bump the package (held package, stale mirror, wrong repo) would still show a
green post_verification and the operator would be told the CVE was fixed.

S1a (round 2): the first fix compared `%{VERSION}-%{RELEASE}` as ONE string.
`rpmvercmp` treats `.`, `-`, `+`, `_` all as plain separators, so a release
digit could slide into a missing version segment: `1.0-2` tokenises to
`[1,0,2]`, `1.0.0-1` to `[1,0,0,1]` — compared position by position, `2 > 0`
at the third slot made `1.0-2` look NEWER than `1.0.0-1`, when rpm compares
VERSION first (`1.0` vs `1.0.0`) and never reaches the release at all. Epoch
was dropped outright — production carries 237 packages with one (`nginx
2:1.20.1-…`, `openssl 1:3.5.5-…`).

S1b: `rpm -q` with no version restriction prints ONE LINE PER INSTALLED
INSTANCE — `kernel` routinely has several at once. Without a trailing
newline in `--qf`, the lines ran together unparseable; naively reading only
the first line would pick whatever order the rpm database happens to
return, not necessarily the newest — a post_verification that reads an OLD
installed kernel out of three would report a successful update as failed
and trigger a rollback of a patch that actually worked.

S1c: `platform.family=debian` used to fail closed unconditionally — true
when written (dpkg-query was not in the executor's allowlist), but the
executor's own round-2 change adds a read-only `dpkg-query` form, and this
host's executor may or may not have picked it up yet. The check now tries
the query and reports the SPECIFIC reason it failed.

Every test here drives `checks.evaluate` through a fake executor client, the
same pattern `test_patch_runner.py` uses, so nothing touches a real package
database.

## Where the two oracle tables came from

`rpm.labelCompare` and `dpkg --compare-versions` are the ONLY authorities
that matter here — a hand-written expectation is just another guess dressed
up as a test. Both were generated ONCE, on 2026-09-08, with Docker:

    docker run --rm almalinux:9 bash -c "
        dnf install -y python3-rpm >/dev/null 2>&1 &&
        python3 -c 'import rpm; print(rpm.labelCompare((e1,v1,r1),(e2,v2,r2)))'"

    docker run --rm debian:bookworm-slim bash -c '
        dpkg --compare-versions "$a" lt "$b" ; echo $?'

(run once per pair; the actual generator scripts drove ~70 curated pairs
each — see `_RPM_ORACLE` and `_DEB_ORACLE` below for the pairs themselves,
chosen to hit the release-fills-a-missing-version-segment bug, epoch
dominance, tilde, and — rpm only — caret).
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from sentinel.errors import ExecutorRejected
from sentinel.patch import checks


def run(c):
    return asyncio.run(c)


def _check(**kw: Any) -> dict[str, Any]:
    return {"kind": "pkg_version", "name": "nginx", **kw}


class _FakeExec:
    """Answers `rpm -q ...` / `dpkg-query -W ...` the way the real binaries
    would, without a real package database.

    `installed` is either one EVR-formatted line, a list of lines (S1b:
    multiply-installed), or `None` (not installed). `refuse` simulates an
    executor whose policy does not (yet) allow the binary — S1c.
    """

    def __init__(self, installed: str | list[str] | None, *, refuse: bool = False):
        self.installed = installed
        self.refuse = refuse
        self.calls: list[list[str]] = []

    def call(self, op: str, **args: Any) -> dict[str, Any]:
        argv = args.get("argv") or []
        self.calls.append(argv)
        binary = argv[0] if argv else ""

        if binary == "rpm":
            assert argv[1] == "-q", argv
        elif binary == "dpkg-query":
            if self.refuse:
                raise ExecutorRejected("refused: dpkg-query not in BINARY_ALLOWLIST")
        else:
            raise AssertionError(f"unexpected op/argv: {op} {argv}")

        if self.installed is None:
            return {"exit_code": 1, "stdout": "", "stderr": "package not installed"}
        lines = self.installed if isinstance(self.installed, list) else [self.installed]
        return {"exit_code": 0, "stdout": "\n".join(lines) + "\n", "stderr": ""}


@pytest.fixture(autouse=True)
def _fake(monkeypatch):
    fake = _FakeExec(installed="(none):1.20.1-2.el9")
    monkeypatch.setattr(checks, "_client", fake)
    return fake


# ---------------------------------------------------------------------------
# rpm -q argv shape — S1b: the query format must end the format string with
# the literal two characters backslash-n (rpm's own escape, not a raw
# newline byte), never a real newline: `executor/policy.py:
# SHELL_METACHARACTERS` refuses any argv element containing an actual "\n",
# so a real newline byte here would make the executor reject the query on
# EVERY call, always — a fix that cannot ever run is not a fix.
# ---------------------------------------------------------------------------
def test_the_rpm_query_format_ends_with_the_two_character_escape_not_a_real_newline(_fake):
    run(checks.evaluate(None, _check(at_least="1.0"), family="rhel"))
    argv = _fake.calls[0]
    fmt = argv[argv.index("--qf") + 1]
    assert "\n" not in fmt, "a real newline byte here is refused outright by executor policy"
    assert fmt.endswith("\\n")
    assert "%{EPOCH}" in fmt and "%{VERSION}" in fmt and "%{RELEASE}" in fmt


def test_dpkg_query_argv_shape(monkeypatch):
    fake = _FakeExec(installed="1.20.1-2")
    monkeypatch.setattr(checks, "_client", fake)
    run(checks.evaluate(None, _check(at_least="1.0"), family="debian"))
    argv = fake.calls[0]
    assert argv[0] == "dpkg-query"
    fmt = argv[argv.index("-f") + 1]
    assert "\n" not in fmt
    assert fmt.endswith("\\n")


# ---------------------------------------------------------------------------
# rhel behaviour
# ---------------------------------------------------------------------------
def test_installed_older_than_at_least_fails(monkeypatch):
    """An apply step that did not actually update the package must not be
    reported as verified — this is the exact scenario S1 left silently green."""
    monkeypatch.setattr(checks, "_client", _FakeExec(installed="(none):1.18.0-1.el9"))
    outcome = run(checks.evaluate(None, _check(at_least="1.20.0-1.el9"), family="rhel"))
    assert outcome.ok is False
    assert "1.18.0-1.el9" in outcome.detail


def test_installed_equal_to_at_least_passes():
    outcome = run(checks.evaluate(None, _check(at_least="1.20.1-2.el9"), family="rhel"))
    assert outcome.ok is True


def test_installed_newer_than_at_least_passes():
    outcome = run(checks.evaluate(None, _check(at_least="1.18.0-1.el9"), family="rhel"))
    assert outcome.ok is True


def test_equals_exact_match_passes():
    outcome = run(checks.evaluate(None, _check(equals="1.20.1-2.el9"), family="rhel"))
    assert outcome.ok is True


def test_equals_mismatch_fails():
    """`equals` is a stricter contract than `at_least`: a NEWER installed
    version must still fail it, because the plan promised an exact pin."""
    outcome = run(checks.evaluate(None, _check(equals="1.20.0-1.el9"), family="rhel"))
    assert outcome.ok is False


def test_not_installed_fails_and_says_so(monkeypatch):
    monkeypatch.setattr(checks, "_client", _FakeExec(installed=None))
    outcome = run(checks.evaluate(None, _check(at_least="1.0"), family="rhel"))
    assert outcome.ok is False
    assert "neinstalat" in outcome.detail


def test_unknown_family_fails_closed():
    outcome = run(checks.evaluate(None, _check(at_least="1.0"), family="suse"))
    assert outcome.ok is False


# --- S7: a hollow `_rpm_vercmp` (a plain string compare) must be caught ---
def test_evaluate_uses_real_rpmvercmp_not_string_compare(monkeypatch):
    """`"1.20.1-10.el9" >= "1.20.1-2.el9"` is FALSE as a plain Python string
    compare (`'1' < '2'` at the first differing character) and TRUE as an
    rpm version compare (10 > 2 numerically). A patch that correctly bumped
    nginx from `.2` to `.10` must not be reported as having failed to
    update — that is the exact shape of alarm that trains an operator to
    stop trusting post_verification.

    Falsified: replacing `_rpm_vercmp`'s body with `-1 if a < b else (0 if a
    == b else 1)` (plain string compare) turns this red — confirmed by hand
    during review, restored immediately after.
    """
    monkeypatch.setattr(checks, "_client", _FakeExec(installed="(none):1.20.1-10.el9"))
    outcome = run(checks.evaluate(None, _check(at_least="1.20.1-2.el9"), family="rhel"))
    assert outcome.ok is True, outcome.detail


# ---------------------------------------------------------------------------
# S1a — the missing-version-segment trap: a plan checking `at_least: 1.0.0-1`
# against an actually-older `1.0-2` must fail, not pass because the OLD
# single-string compare read the release digit as if it were a version
# segment.
# ---------------------------------------------------------------------------
def test_the_release_digit_does_not_fill_a_missing_version_segment(monkeypatch):
    monkeypatch.setattr(checks, "_client", _FakeExec(installed="(none):1.0-2"))
    outcome = run(checks.evaluate(None, _check(at_least="1.0.0-1"), family="rhel"))
    assert outcome.ok is False, (
        "1.0-2 read as satisfying at_least 1.0.0-1 — the release's '2' filled "
        "the version's missing third segment, the S1a bug")


# ---------------------------------------------------------------------------
# S1a — epoch: production carries packages with one (nginx, openssl); an
# epoch bump must win outright even when the version/release text alone
# would look like a downgrade.
# ---------------------------------------------------------------------------
def test_an_epoch_bump_satisfies_at_least_even_if_the_version_text_looks_older(monkeypatch):
    monkeypatch.setattr(checks, "_client", _FakeExec(installed="2:1.0.0-1.el9"))
    outcome = run(checks.evaluate(None, _check(at_least="1:9.9.9-99.el9"), family="rhel"))
    assert outcome.ok is True, outcome.detail
    assert "2:1.0.0-1.el9" in outcome.detail


def test_a_missing_epoch_is_read_as_zero_not_dropped(monkeypatch):
    """Before S1a, epoch was not parsed at all — an installed package with
    epoch 2 and a target with no epoch (implicitly 0) must compare as
    NEWER, not as equal-by-coincidence because epoch was thrown away."""
    monkeypatch.setattr(checks, "_client", _FakeExec(installed="2:1.20.1-1.el9"))
    outcome = run(checks.evaluate(None, _check(equals="1.20.1-1.el9"), family="rhel"))
    assert outcome.ok is False, (
        "installed epoch 2 vs a target with no epoch (0) compared equal — "
        "epoch was dropped, the exact S1a gap")


# ---------------------------------------------------------------------------
# S1b — multiply-installed packages (kernel): the MAXIMUM installed instance
# is what "did the update land" actually asks about.
# ---------------------------------------------------------------------------
def test_three_installed_kernels_the_newest_one_satisfies_at_least(monkeypatch):
    monkeypatch.setattr(checks, "_client", _FakeExec(installed=[
        "(none):5.14.0-284.11.1.el9", "(none):5.14.0-362.8.1.el9",
        "(none):5.14.0-427.13.1.el9",
    ]))
    outcome = run(checks.evaluate(
        None, _check(name="kernel", at_least="5.14.0-427.13.1.el9"), family="rhel"))
    assert outcome.ok is True, outcome.detail
    assert "3 instanțe" in outcome.detail


def test_three_installed_kernels_reading_only_the_first_line_would_be_wrong(monkeypatch):
    """The oldest kernel line first in rpm's own (unordered) output must not
    be what the check reads — that would report a successful update as
    failed and could trigger an unnecessary rollback."""
    monkeypatch.setattr(checks, "_client", _FakeExec(installed=[
        "(none):5.14.0-284.11.1.el9",   # oldest, listed first
        "(none):5.14.0-427.13.1.el9",   # newest — the one just installed
    ]))
    outcome = run(checks.evaluate(
        None, _check(name="kernel", at_least="5.14.0-400.0.0.el9"), family="rhel"))
    assert outcome.ok is True, (
        "reading only the first (oldest) installed line failed a check that "
        "the newest installed kernel actually satisfies")


# ---------------------------------------------------------------------------
# debian — S1c
# ---------------------------------------------------------------------------
def test_debian_installed_satisfies_at_least(monkeypatch):
    monkeypatch.setattr(checks, "_client", _FakeExec(installed="1.20.1-2"))
    outcome = run(checks.evaluate(None, _check(at_least="1.18.0-1"), family="debian"))
    assert outcome.ok is True, outcome.detail


def test_debian_installed_older_than_at_least_fails(monkeypatch):
    monkeypatch.setattr(checks, "_client", _FakeExec(installed="1.18.0-1"))
    outcome = run(checks.evaluate(None, _check(at_least="1.20.1-2"), family="debian"))
    assert outcome.ok is False


def test_debian_not_installed_fails_and_says_so(monkeypatch):
    monkeypatch.setattr(checks, "_client", _FakeExec(installed=None))
    outcome = run(checks.evaluate(None, _check(at_least="1.0"), family="debian"))
    assert outcome.ok is False
    assert "neinstalat" in outcome.detail


def test_debian_fails_closed_with_the_specific_reason_when_the_executor_refuses(monkeypatch):
    """S1c: the executor on THIS host may not have the round-2 dpkg-query
    allowlist entry yet — that must read differently from "not installed"
    or a crash, and differently from the OLD blanket "not implemented"
    message (which would now be wrong on an upgraded host)."""
    monkeypatch.setattr(checks, "_client", _FakeExec(installed="1.0", refuse=True))
    outcome = run(checks.evaluate(None, _check(at_least="1.0"), family="debian"))
    assert outcome.ok is False
    assert "dpkg-query" in outcome.detail
    assert "nu e permis de executor" in outcome.detail


def test_debian_multiply_installed_uses_the_newest(monkeypatch):
    monkeypatch.setattr(checks, "_client", _FakeExec(installed=["1.18.0-1", "1.20.1-2"]))
    outcome = run(checks.evaluate(None, _check(at_least="1.20.0-1"), family="debian"))
    assert outcome.ok is True, outcome.detail


# ---------------------------------------------------------------------------
# The rpm EVR comparator itself, isolated — the oracle table.
#
# Generated once against `rpm.labelCompare` in `almalinux:9` (command in the
# module docstring). Each row is `((epoch, version, release), (epoch,
# version, release), expected)`; `_rpm_evr_cmp` takes the same two EVRs as
# `%{EPOCH}:%{VERSION}-%{RELEASE}`-shaped strings, with an absent epoch
# spelled `None` here and `(none)` the way `rpm -q` actually prints it.
# ---------------------------------------------------------------------------
_RPM_ORACLE: list[tuple[tuple[str | None, str, str], tuple[str | None, str, str], int]] = [
    ((None, '1.2.3', '1'), (None, '1.2.3', '1'), 0),
    ((None, '1.2.4', '1'), (None, '1.2.3', '1'), 1),
    ((None, '1.2.3', '1'), (None, '1.2.4', '1'), -1),
    ((None, '2.0', '1'), (None, '1.99', '1'), 1),
    ((None, '1.0', '1'), (None, '1.0', '2'), -1),
    ((None, '1.0', '2'), (None, '1.0', '1'), 1),
    ((None, '1.0', '2'), (None, '1.0.0', '1'), -1),
    ((None, '1.0.0', '1'), (None, '1.0', '2'), 1),
    ((None, '1.20.1', '2.el9'), (None, '1.20.1', '10.el9'), -1),
    ((None, '1.20.1', '10.el9'), (None, '1.20.1', '2.el9'), 1),
    ((None, '1.1', '1'), (None, '1.1.1', '1'), -1),
    ((None, '1.1.1', '1'), (None, '1.1', '1'), 1),
    ((None, '1.0~rc1', '1'), (None, '1.0', '1'), -1),
    ((None, '1.0', '1'), (None, '1.0~rc1', '1'), 1),
    ((None, '1.0~rc1', '1'), (None, '1.0~rc2', '1'), -1),
    ((None, '1.0~rc2', '1'), (None, '1.0~rc1', '1'), 1),
    ((None, '1.0~~', '1'), (None, '1.0~rc1', '1'), -1),
    ((None, '1.0~rc1~git1', '1'), (None, '1.0~rc1', '1'), -1),
    ((None, '1.0~rc1', '1'), (None, '1.0~rc1~git1', '1'), 1),
    ((None, '1.0^', '1'), (None, '1.0', '1'), 1),
    ((None, '1.0', '1'), (None, '1.0^', '1'), -1),
    ((None, '1.0^git1', '1'), (None, '1.0', '1'), 1),
    ((None, '1.0', '1'), (None, '1.0^git1', '1'), -1),
    ((None, '1.0^git1', '1'), (None, '1.0.1', '1'), -1),
    ((None, '1.0.1', '1'), (None, '1.0^git1', '1'), 1),
    ((None, '1.0^git1', '1'), (None, '1.0^git2', '1'), -1),
    # These two, unlike the pair above, cannot be satisfied by accident: a
    # caret branch that is simply deleted (falls through to "empty alpha
    # segment") returns -1 for EITHER direction of a caret/caret comparison,
    # which matches `1.0^git1` vs `1.0^git2` by coincidence but is caught
    # here by its mirror image.
    ((None, '1.0^git2', '1'), (None, '1.0^git1', '1'), 1),
    ((None, '1.0^git1', '1'), (None, '1.0^', '1'), 1),
    ((None, '1.0~rc1', '1'), (None, '1.0^git1', '1'), -1),
    ((None, '1.0^git1', '1'), (None, '1.0~rc1', '1'), 1),
    (('1', '9.9.9', '99'), ('2', '1.0.0', '1'), -1),
    (('2', '1.0.0', '1'), ('1', '9.9.9', '99'), 1),
    (('1', '1.0', '1'), ('1', '1.0', '1'), 0),
    (('0', '1.0', '1'), (None, '1.0', '1'), 0),
    (('2', '1.20.1', '1.el9'), (None, '1.20.1', '1.el9'), 1),
    ((None, '1.20.1', '1.el9'), ('2', '1.20.1', '1.el9'), -1),
    (('1', '1.0', '1'), (None, '9.0', '1'), 1),
    (('2', '1.20.1', '10.el9'), ('2', '1.20.1', '2.el9'), 1),
    (('2', '1.20.1', '2.el9'), ('2', '1.20.1', '10.el9'), -1),
    (('1', '3.5.5', '1.el9'), ('1', '3.5.4', '1.el9'), 1),
    (('1', '3.5.4', '1.el9'), ('1', '3.5.5', '1.el9'), -1),
    (('1', '3.5.5', '1.el9'), (None, '3.5.5', '1.el9'), 1),
    ((None, '1.0', '1'), (None, '1.0a', '1'), -1),
    ((None, '1.0a', '1'), (None, '1.0', '1'), 1),
    ((None, '1.0.a', '1'), (None, '1.0.1', '1'), -1),
    ((None, '1.0.1', '1'), (None, '1.0.a', '1'), 1),
    ((None, '1.0a', '1'), (None, '1.0b', '1'), -1),
    ((None, '1.0b', '1'), (None, '1.0a', '1'), 1),
    ((None, '1.0alpha', '1'), (None, '1.0beta', '1'), -1),
    ((None, '1.007', '1'), (None, '1.7', '1'), 0),
    ((None, '1.7', '1'), (None, '1.007', '1'), 0),
    ((None, '1.0', '01'), (None, '1.0', '1'), 0),
    ((None, '1.0.0', '1'), (None, '1_0_0', '1'), 0),
    ((None, '1.0+build1', '1'), (None, '1.0.build1', '1'), 0),
    ((None, '1.2.3.4', '1'), (None, '1.2.3', '1'), 1),
    ((None, '1.2.3', '1'), (None, '1.2.3.4', '1'), -1),
    ((None, '1.2.3.0', '1'), (None, '1.2.3', '1'), 1),
    ((None, '1.20.1', '1.el9_3'), (None, '1.20.1', '1.el9'), 1),
    ((None, '1.20.1', '1.el9'), (None, '1.20.1', '1.el9_3'), -1),
    ((None, '1.20.1', '2'), (None, '1.20.1', '2.1'), -1),
    ((None, '1.0', '1'), (None, '1.0', '01'), 0),
    (('2', '1.20.1', '14.el9'), ('2', '1.20.1', '14.el9_3.1'), -1),
    (('2', '1.20.1', '14.el9_3.1'), ('2', '1.20.1', '14.el9'), 1),
    (('1', '3.5.5', '1.el9'), ('1', '3.5.5', '2.el9'), -1),
    ((None, '5.0', '1'), (None, '5.0', '1'), 0),
    ((None, '5.0', '1'), (None, '5.0', '2'), -1),
    ((None, '1.0', '1~rc1'), (None, '1.0', '1'), -1),
    ((None, '1.0', '1'), (None, '1.0', '1~rc1'), 1),
    ((None, '2.4^', '1'), (None, '2.4.1', '1'), -1),
    ((None, '2.4.1', '1'), (None, '2.4^', '1'), 1),
]


def _rpm_evr_str(e: str | None, v: str, r: str) -> str:
    return f"(none):{v}-{r}" if e is None else f"{e}:{v}-{r}"


@pytest.mark.parametrize("a,b,expected", _RPM_ORACLE)
def test_rpm_evr_cmp_matches_rpm_labelCompare(a, b, expected):
    assert checks._rpm_evr_cmp(_rpm_evr_str(*a), _rpm_evr_str(*b)) == expected


def test_the_rpm_oracle_table_has_at_least_sixty_pairs():
    assert len(_RPM_ORACLE) >= 60


# ---------------------------------------------------------------------------
# The debian EVR comparator, isolated — the oracle table.
#
# Generated once against `dpkg --compare-versions` in `debian:bookworm-slim`
# (command in the module docstring). Each row is `(a, b, expected)` where a
# and b are full `epoch:version-release` strings.
# ---------------------------------------------------------------------------
_DEB_ORACLE: list[tuple[str, str, int]] = [
    ("1.2.3-1", "1.2.3-1", 0),
    ("1.2.4-1", "1.2.3-1", 1),
    ("1.2.3-1", "1.2.4-1", -1),
    ("2.0-1", "1.99-1", 1),
    ("1.0-1", "1.0-2", -1),
    ("1.0-2", "1.0-1", 1),
    ("1.0-2", "1.0.0-1", -1),
    ("1.0.0-1", "1.0-2", 1),
    ("1:1.0-1", "2:1.0-1", -1),
    ("2:1.0-1", "1:1.0-1", 1),
    ("1:1.0-1", "1.0-1", 1),
    ("1.0-1", "1:1.0-1", -1),
    ("0:1.0-1", "1.0-1", 0),
    ("2:1.20.1-1", "1.20.1-999", 1),
    ("1.20.1-999", "2:1.20.1-1", -1),
    ("1.0~rc1-1", "1.0-1", -1),
    ("1.0-1", "1.0~rc1-1", 1),
    ("1.0~rc1-1", "1.0~rc2-1", -1),
    ("1.0~rc2-1", "1.0~rc1-1", 1),
    ("1.0~~-1", "1.0~rc1-1", -1),
    ("1.0~rc1~git1-1", "1.0~rc1-1", -1),
    ("1.0~rc1-1", "1.0~rc1~git1-1", 1),
    ("1.0-1~rc1", "1.0-1", -1),
    ("1.0-1", "1.0-1~rc1", 1),
    ("1.0a-1", "1.0-1", 1),
    ("1.0-1", "1.0a-1", -1),
    ("1.0a-1", "1.0b-1", -1),
    ("1.0b-1", "1.0a-1", 1),
    ("1.0A-1", "1.0a-1", -1),
    ("1.0a-1", "1.0A-1", 1),
    ("1.007-1", "1.7-1", 0),
    ("1.7-1", "1.007-1", 0),
    ("1.0-01", "1.0-1", 0),
    ("1.2.3.4-1", "1.2.3-1", 1),
    ("1.2.3-1", "1.2.3.4-1", -1),
    ("1.2.3.0-1", "1.2.3-1", 1),
    ("3.5.5-1", "3.5.4-1", 1),
    ("3.5.4-1", "3.5.5-1", -1),
    ("1.20.1-1ubuntu1", "1.20.1-1", 1),
    ("1.20.1-1", "1.20.1-1ubuntu1", -1),
    ("1.20.1+dfsg-1", "1.20.1-1", 1),
    ("1.20.1-1", "1.20.1+dfsg-1", -1),
    ("1.0-1", "1.0-1.1", -1),
    ("1.0-1.1", "1.0-1", 1),
    ("1.0", "1.0-0", 0),
    ("1.0-0", "1.0", 0),
    ("1.0", "1.0-1", -1),
    ("5.0-1", "5.0-1", 0),
    ("5.0-1", "5.0-2", -1),
    ("1.20.1-14", "1.20.1-14+deb12u1", -1),
    ("1.20.1-14+deb12u1", "1.20.1-14", 1),
]


@pytest.mark.parametrize("a,b,expected", _DEB_ORACLE)
def test_deb_evr_cmp_matches_dpkg_compare_versions(a, b, expected):
    assert checks._deb_evr_cmp(a, b) == expected


def test_the_deb_oracle_table_has_at_least_forty_pairs():
    assert len(_DEB_ORACLE) >= 40
