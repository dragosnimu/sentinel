"""Evaluate the structured checks a patch plan declares.

Preflight, health_check and post_verification are not free-form commands: each
is a `{kind, ...}` object the plan author picked from a fixed vocabulary. That
matters for safety — "is nginx active?" expressed as `{"kind": "systemd", "unit":
"nginx.service", "expect_state": "active"}` cannot be turned into anything else,
whereas the same question expressed as a shell command can.

Only the `command` kind reaches the executor, and it does so through the same
validated-argv path as an apply step. Every other kind is answered by a targeted
query the executor already exposes.

A check that cannot be evaluated is a FAILED check, never a passing one. The
alternative — treating "I could not tell" as "fine" — is how a patch proceeds
against a machine nobody actually verified.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

from sentinel.db.engine import Database
from sentinel.errors import ExecutorRejected
from sentinel.logging_setup import get_logger
from sentinel.respond.executor_client import TIMEOUT_MARGIN_S, ExecutorClient

log = get_logger(__name__)

_client = ExecutorClient()


@dataclass
class CheckOutcome:
    ok: bool
    detail: str
    kind: str = ""


async def _exec(argv: list[str], timeout: int = 30) -> dict[str, Any]:
    # socket_timeout_s covers the check's own timeout (up to 3600s for a
    # "command" check) plus margin, so the client does not give up on a
    # still-running check before the executor itself would time it out.
    return await asyncio.to_thread(
        _client.call, "patch_step_exec", argv=argv, timeout_s=timeout,
        socket_timeout_s=timeout + TIMEOUT_MARGIN_S)


async def evaluate(db: Database, check: dict[str, Any], *, family: str = "rhel") -> CheckOutcome:
    """Run one check. Never raises: an error is a failed check.

    `family` is `platform.family` from the running config — which package
    manager and version syntax `pkg_version` must speak. It defaults to
    `rhel` for the same reason `PlatformConfig.family` does (see its
    docstring): every caller that predates this parameter runs on AlmaLinux.
    """
    kind = str(check.get("kind", ""))
    try:
        return await _dispatch(db, kind, check, family)
    except Exception as exc:  # noqa: BLE001 - unevaluable is failed, not passed
        return CheckOutcome(False, f"verificarea nu a putut fi evaluată: {exc}", kind)


async def _dispatch(db: Database, kind: str, c: dict[str, Any], family: str) -> CheckOutcome:
    if kind == "systemd":
        unit, expect = str(c["unit"]), str(c["expect_state"])
        res = await _exec(["systemctl", "is-active", unit])
        state = str(res.get("stdout", "")).strip()
        return CheckOutcome(state == expect, f"{unit} este {state!r}, așteptat {expect!r}", kind)

    if kind == "command":
        argv = [str(a) for a in c["argv"]]
        expect = [int(x) for x in c.get("expect_exit", [0])]
        res = await _exec(argv, timeout=int(c.get("timeout_s", 60)))
        code = res.get("exit_code")
        return CheckOutcome(code in expect, f"cod {code}, așteptat {expect}", kind)

    if kind == "file_exists":
        res = await _exec(["test", "-e", str(c["path"])])
        return CheckOutcome(res.get("exit_code") == 0, f"{c['path']} există", kind)

    if kind == "file_absent":
        res = await _exec(["test", "-e", str(c["path"])])
        return CheckOutcome(res.get("exit_code") != 0, f"{c['path']} lipsește", kind)

    if kind == "pkg_version":
        return await _check_pkg_version(c, family)

    if kind == "disk_free":
        info = await asyncio.to_thread(_client.call, "disk_free", path=str(c["path"]))
        free = int(info.get("free", 0))
        need = int(c["min_bytes"])
        return CheckOutcome(free >= need,
                            f"{free // 1_048_576} MB liberi, necesari {need // 1_048_576} MB",
                            kind)

    if kind == "no_open_incident":
        # Patching a machine that is actively under attack turns two problems
        # into one confusing one.
        n = int(await db.fetchval(
            "SELECT count(*) FROM incidents WHERE status IN ('open','acknowledged') "
            "AND severity IN ('high','critical') "
            # Cast for the same reason as in repo/patches.py: a parameter whose
            # only other appearance is a bare IS NULL cannot always be inferred.
            "AND (asset_id = $1::bigint OR $1::bigint IS NULL)",
            c.get("asset_id")) or 0)
        return CheckOutcome(n == 0, f"{n} incidente grave deschise", kind)

    if kind == "file_sha256":
        res = await _exec(["sha256sum", str(c["path"])])
        actual = str(res.get("stdout", "")).split()[0] if res.get("stdout") else ""
        return CheckOutcome(actual == str(c["sha256"]),
                            f"sha256 {'corespunde' if actual == str(c['sha256']) else 'diferit'}",
                            kind)

    if kind in ("http", "tcp", "docker"):
        # These need a network probe or the docker socket. The health prober
        # already owns those; wiring them here would duplicate that logic with
        # slightly different timeouts, which is how two answers to one question
        # appear. Declared unsupported rather than silently passing.
        return CheckOutcome(False, f"verificarea {kind} nu este încă implementată "
                                   "în runner — folosește kind 'command'", kind)

    return CheckOutcome(False, f"tip de verificare necunoscut: {kind}", kind)


# ---------------------------------------------------------------------------
# pkg_version — S1: this used to read `expect_version`, a key no validated
# plan can contain (`validator.py` requires `equals` or `at_least`), so the
# check only ever asked "is it installed at all" and passed regardless of
# which version. A patch whose apply step silently failed to update the
# package — a repo pin, a held package, a mirror serving the old build —
# would still show a green post_verification.
#
# S1a (round 2): the first fix compared `%{VERSION}-%{RELEASE}` as ONE
# string, with no split between version and release. `rpmvercmp` tokenises
# on `.`, `-`, `+`, `_` alike — they are all just separators to it — so a
# release digit could slide into a missing version segment: `1.0-2` tokenises
# to `[1,0,2]`, `1.0.0-1` tokenises to `[1,0,0,1]`; compared segment by
# segment, `2 > 0` at the third slot makes `1.0-2` look newer than
# `1.0.0-1`, when the real rpm compares VERSION first (`1.0` vs `1.0.0`,
# `1.0.0` wins on the extra segment) and never even reaches the release.
# Measured against `rpm.labelCompare` (the `almalinux:9` oracle, see
# `tests/unit/test_patch_checks.py`): 11 of 56 hand-picked pairs disagreed
# with the old single-string compare. Epoch was also silently dropped —
# production carries 237 packages with one (`nginx 2:1.20.1-…`,
# `openssl 1:3.5.5-…`) — so an epoch bump (which always wins outright,
# regardless of version/release) could not be told from no change at all.
# ---------------------------------------------------------------------------


def _rpm_order(ch: str) -> int:
    """A single rpmvercmp separator/letter's sort key: `~` is lowest (even
    below nothing), a letter sorts by its own code point, anything else
    (including "no character left") sorts as 0 — it is a plain separator to
    rpm's tokeniser and carries no ordering weight of its own."""
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return 0


def _rpm_vercmp(a: str, b: str) -> int:
    """Compare two rpm VERSION-only or RELEASE-only strings the way `rpm`
    itself orders them: -1, 0 or 1. NOT an EVR string — see `_rpm_evr_cmp`,
    which splits epoch:version-release first and calls this once for the
    version half and once for the release half. Calling this directly on a
    combined `version-release` string is exactly the S1a bug above.

    A line-for-line port of rpm's own `rpmvercmp()` (`lib/rpmvercmp.c`):
    walk both strings in lockstep, alternating between runs of separator
    characters (compared one at a time — `~` sorts before everything
    including the end of the string, `^` sorts after everything but before a
    longer real segment following it) and runs of digits or letters (never
    mixed — a digit run always outranks a letter run at the same position,
    numeric runs compare by numeric value with leading zeros stripped,
    letter runs compare lexically). Verified against `rpm.labelCompare` on
    68 pairs including every one of these rules — see the oracle table in
    `test_patch_checks.py`.
    """
    if a == b:
        return 0
    one, two = a, b
    la, lb = len(one), len(two)
    i = j = 0

    while i < la or j < lb:
        while i < la and not (one[i].isalnum() or one[i] in "~^"):
            i += 1
        while j < lb and not (two[j].isalnum() or two[j] in "~^"):
            j += 1

        c1 = one[i] if i < la else ""
        c2 = two[j] if j < lb else ""

        # Tilde sorts before everything, including a missing segment.
        if c1 == "~" or c2 == "~":
            if c1 != "~":
                return 1
            if c2 != "~":
                return -1
            i += 1
            j += 1
            continue

        # Caret sorts after everything but a real (non-caret) longer
        # segment following it, and before an end-of-string on the other
        # side — the reverse of tilde.
        if c1 == "^" or c2 == "^":
            if c1 == "":
                return -1
            if c2 == "":
                return 1
            if c1 != "^":
                return 1
            if c2 != "^":
                return -1
            i += 1
            j += 1
            continue

        if i >= la or j >= lb:
            break

        if one[i].isdigit():
            start_i = i
            while i < la and one[i].isdigit():
                i += 1
            start_j = j
            while j < lb and two[j].isdigit():
                j += 1
            isnum = True
        else:
            start_i = i
            while i < la and one[i].isalpha():
                i += 1
            start_j = j
            while j < lb and two[j].isalpha():
                j += 1
            isnum = False

        seg1 = one[start_i:i]
        seg2 = two[start_j:j]

        # A run present on one side and absent on the other (different
        # class at this position): a numeric run always outranks an alpha
        # one, which is why `1.0` beats `1.0a` and `2.0` beats `2.0rc1`.
        if not seg2:
            return 1 if isnum else -1

        if isnum:
            s1 = seg1.lstrip("0") or "0"
            s2 = seg2.lstrip("0") or "0"
            if len(s1) != len(s2):
                return 1 if len(s1) > len(s2) else -1
            if s1 != s2:
                return 1 if s1 > s2 else -1
        else:
            if seg1 != seg2:
                return 1 if seg1 > seg2 else -1
        # Equal segment — the loop continues from where i/j already are.

    if i >= la and j >= lb:
        return 0
    # Whichever side still has real content left is newer, UNLESS that
    # leftover content starts with `~` (older) — reachable in principle
    # (rpm's own source keeps the same check), though every case actually
    # observed here resolves inside the loop's own tilde/caret branches
    # first.
    if i >= la:
        if j < lb and two[j] == "~":
            return 1
        if j < lb and two[j] == "^":
            return -1
        return -1
    if one[i] == "~":
        return -1
    if one[i] == "^":
        return 1
    return 1


_EPOCH_RE = re.compile(r"^(?:\((none)\)|(\d+)):")


def _parse_rpm_evr(s: str) -> tuple[int, str, str]:
    """Split `epoch:version-release` into `(epoch, version, release)`.

    `rpm -q --qf '%{EPOCH}:...'` prints the literal string `(none)` for a
    package with no epoch set — not an empty string — so that is the other
    spelling of "epoch 0" this recognises, on top of a genuinely absent
    prefix (a target string from a plan, which is not required to name an
    epoch it does not care about). Version and release split on the LAST
    `-`: rpm packaging convention forbids a `-` inside either component, so
    the final one is always the version/release boundary. A string with no
    `-` at all (rare, but a plan author's `equals`/`at_least` target could
    omit the release) yields an empty release, which sorts as "nothing left"
    against a real release the same way `_rpm_vercmp` already treats that.
    """
    m = _EPOCH_RE.match(s)
    if m:
        epoch = 0 if m.group(1) else int(m.group(2))
        rest = s[m.end():]
    else:
        epoch = 0
        rest = s
    if "-" in rest:
        version, release = rest.rsplit("-", 1)
    else:
        version, release = rest, ""
    return epoch, version, release


def _rpm_evr_cmp(a: str, b: str) -> int:
    """Full EVR compare: epoch numerically first (it wins outright — an
    epoch bump means "this is a deliberately renumbered, newer package" by
    rpm convention, regardless of what the version/release text says), then
    version, then release."""
    ea, va, ra = _parse_rpm_evr(a)
    eb, vb, rb = _parse_rpm_evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    cmp_v = _rpm_vercmp(va, vb)
    if cmp_v != 0:
        return cmp_v
    return _rpm_vercmp(ra, rb)


def _format_evr(epoch: int, version: str, release: str) -> str:
    """The display form an operator actually reads — epoch prefix only when
    it is non-zero, matching how `rpm -q` (without an explicit `%{EPOCH}`)
    already prints these everywhere else in this codebase's messages."""
    base = f"{version}-{release}" if release else version
    return f"{epoch}:{base}" if epoch else base


# ---------------------------------------------------------------------------
# Debian/Ubuntu — S1c: `platform.family=debian` used to fail closed with a
# fixed "no binary in the allowlist" message, which was true when it was
# written but is no longer the only reason this can fail: the executor's
# round-2 allowlist gained read-only `dpkg-query`/`rpm -q` forms, but ONLY on
# hosts running that updated executor build. This check must not assume the
# executor it happens to be talking to has caught up with this code — it
# tries the query and reports the SPECIFIC reason (still refused vs. some
# other failure) rather than a blanket "not implemented" that would now be
# wrong on an upgraded host and misleading on one that is not.
# ---------------------------------------------------------------------------
_DEB_EPOCH_RE = re.compile(r"^(\d+):")


def _deb_order(ch: str) -> int:
    """dpkg's per-character sort key outside a digit run: `~` sorts before
    everything (even the end of the string), a letter sorts by ASCII code
    point (so uppercase sorts before lowercase — `A` < `a`, unlike rpm's
    letter-run comparison), and everything else (`.`, `+`, `-` inside a
    component, ...) sorts AFTER every letter. `""` (end of string) is 0,
    the same value a digit position gets — that is what makes an ended
    string compare as "nothing", below a following letter but above `~`."""
    if ch == "":
        return 0
    if ch.isdigit():
        return 0
    if ch.isalpha():
        return ord(ch)
    if ch == "~":
        return -1
    return ord(ch) + 256


def _deb_vercmp(a: str, b: str) -> int:
    """Compare two Debian upstream-version-only or revision-only strings the
    way `dpkg --compare-versions` orders them: -1, 0 or 1. A line-for-line
    port of dpkg's own `verrevcmp()` (`lib/dpkg/version.c`): alternate
    between a run of non-digit characters (compared one character at a time
    via `_deb_order`) and a run of digits (compared as a big number, leading
    zeros stripped). Verified against `dpkg --compare-versions` on 51 pairs
    — see the oracle table in `test_patch_checks.py`.
    """
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < la else 0
            bc = _deb_order(b[j]) if j < lb else 0
            if ac != bc:
                return 1 if ac > bc else -1
            if i < la:
                i += 1
            if j < lb:
                j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and a[i].isdigit() and b[j].isdigit():
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return 1 if first_diff > 0 else -1
    return 0


def _parse_deb_evr(s: str) -> tuple[int, str, str]:
    """Split `epoch:upstream_version-debian_revision` the way dpkg does. A
    missing epoch is 0; a missing revision (no `-` at all — legal, and
    common for a target string a plan author wrote without one) is an EMPTY
    string, not `"0"` — `_deb_vercmp("", "0")` already compares equal
    (leading zeros strip to nothing on both sides), so this does not need
    to invent a value dpkg itself does not use."""
    m = _DEB_EPOCH_RE.match(s)
    if m:
        epoch = int(m.group(1))
        rest = s[m.end():]
    else:
        epoch = 0
        rest = s
    if "-" in rest:
        version, revision = rest.rsplit("-", 1)
    else:
        version, revision = rest, ""
    return epoch, version, revision


def _deb_evr_cmp(a: str, b: str) -> int:
    ea, va, ra = _parse_deb_evr(a)
    eb, vb, rb = _parse_deb_evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    cmp_v = _deb_vercmp(va, vb)
    if cmp_v != 0:
        return cmp_v
    return _deb_vercmp(ra, rb)


def _best_installed(lines: list[str], evr_cmp: Any) -> str:
    """S1b: `rpm -q` (no package version restriction) prints ONE LINE PER
    INSTALLED INSTANCE — `kernel` routinely has several at once, by design,
    so the currently-running one can be rolled back to. Without a trailing
    newline in the `--qf` format the lines ran together into one
    unparseable blob; with it, the naive fix would still be to read only the
    FIRST line, which is whatever order rpm's package database happens to
    return — not necessarily the newest. A post_verification check that
    picks an old kernel EVR out of three installed ones would report the
    just-applied update as failed and trigger a rollback of a patch that
    actually succeeded. The maximum by version compare is what the plan
    is actually asking about: "is at least one installed instance new
    enough" — that is what booting the new kernel next reboot depends on.
    """
    best = lines[0]
    for line in lines[1:]:
        if evr_cmp(line, best) > 0:
            best = line
    return best


async def _check_pkg_version(c: dict[str, Any], family: str) -> CheckOutcome:
    name = str(c["name"])
    equals = c.get("equals")
    at_least = c.get("at_least")
    op, target = ("=", str(equals)) if equals else (">=", str(at_least))

    if family == "rhel":
        # S1b: the LITERAL two characters backslash-n, not a real newline
        # byte — `executor/policy.py:SHELL_METACHARACTERS` refuses any argv
        # element containing an actual "\n", so a genuine newline byte here
        # would make the executor reject the query outright, always. rpm's
        # own `--qf` format engine parses a backslash-n escape in the format
        # STRING and renders a real newline in ITS OWN output — the same
        # thing `rpm -qa --qf '%{NAME}\n'` does at a shell prompt, where the
        # shell (not rpm) is what would turn a raw newline into something
        # else if one were typed instead.
        res = await _exec(["rpm", "-q", "--qf", "%{EPOCH}:%{VERSION}-%{RELEASE}\\n", name])
        if res.get("exit_code") != 0:
            return CheckOutcome(False, f"neinstalat, așteptat {op} {target}", "pkg_version")
        lines = [ln for ln in str(res.get("stdout", "")).splitlines() if ln.strip()]
        if not lines:
            return CheckOutcome(False, f"neinstalat, așteptat {op} {target}", "pkg_version")
        raw = _best_installed(lines, _rpm_evr_cmp)
        installed = _format_evr(*_parse_rpm_evr(raw))
        cmp_result = _rpm_evr_cmp(raw, target)
        ok = cmp_result == 0 if op == "=" else cmp_result >= 0
        multi = f" ({len(lines)} instanțe instalate, cea mai nouă folosită)" if len(lines) > 1 else ""
        return CheckOutcome(
            ok, f"instalat {installed}{multi}, așteptat {op} {target}"
                + ("" if ok else " — nesatisfăcut"),
            "pkg_version")

    if family == "debian":
        try:
            # Same escape rule as the rpm branch above: the literal two
            # characters backslash-n, which dpkg-query's own `-f` format
            # engine turns into a real newline in its output — a raw
            # newline byte in the argv would be refused by the executor's
            # own policy before it ever reached dpkg-query.
            res = await _exec(["dpkg-query", "-W", "-f", "${Version}\\n", name])
        except ExecutorRejected:
            # S1c: fails CLOSED with the honest reason, not the old blanket
            # "not implemented" — this host's executor may or may not have
            # picked up the read-only dpkg-query allowlist entry yet, and
            # "refused" here means specifically THAT, not "crashed" or
            # "package not found" (those come back as data, not a refusal).
            return CheckOutcome(
                False,
                "dpkg-query nu e permis de executor pe această gazdă încă",
                "pkg_version")
        if res.get("exit_code") != 0:
            return CheckOutcome(False, f"neinstalat, așteptat {op} {target}", "pkg_version")
        lines = [ln for ln in str(res.get("stdout", "")).splitlines() if ln.strip()]
        if not lines:
            return CheckOutcome(False, f"neinstalat, așteptat {op} {target}", "pkg_version")
        raw = _best_installed(lines, _deb_evr_cmp)
        installed = _format_evr(*_parse_deb_evr(raw))
        cmp_result = _deb_evr_cmp(raw, target)
        ok = cmp_result == 0 if op == "=" else cmp_result >= 0
        multi = f" ({len(lines)} instanțe instalate, cea mai nouă folosită)" if len(lines) > 1 else ""
        return CheckOutcome(
            ok, f"instalat {installed}{multi}, așteptat {op} {target}"
                + ("" if ok else " — nesatisfăcut"),
            "pkg_version")

    return CheckOutcome(
        False, f"platform.family={family!r} necunoscută pentru pkg_version", "pkg_version")
