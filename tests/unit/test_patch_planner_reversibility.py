"""`sentinel/patch/planner.py` — `risk.reversible` is the model's OWN claim; the
validator enforces only the directions it can observe, and the planner never
overwrites it.

The incident this file covers, measured on the production host on
25 September 2026: patch plan #10 (webkit2gtk3-jsc, CVE-2026-3909) wrote a
correct-looking `dnf downgrade` command into `backup[].restore_argv`, then
declared `risk.reversible: false` with an EMPTY `rollback` section — and
`sentinel/patch/window.py:evaluate` refuses forever the moment it reads
`risk.reversible is False`, which is the door the operator watched close on
a plan a human had already confirmed was recoverable that day.

Three designs, two of them rejected — the history is here because each
rejection is a test below:

  Round 1 OVERWROTE `risk.reversible` with `true` whenever `rollback` was
  non-empty. Six schema-valid rollbacks proved that unsound — none restores
  anything, all six made the overwrite say `true`:

    A `["systemctl", "restart", "nginx.service"]`   — not a package rollback
    B `["dnf", "-y", "reinstall", "nginx"]`          — reinstalls the NEW version
    C `["dnf", "-y", "clean", "all"]`                — touches no package state
    D `["dnf", "-y", "update", "nginx"]`             — the apply step run again
    E rollback pins ONLY ONE of two packages the apply step touched
    G `["dnf", "-y", "makecache"]`                   — touches no package state

  Round 2 REFUSED `reversible: false` when the rollback pinned a verified
  version for every package the apply step touches. Unsound the other way:
  `dnf downgrade` is `goal.install` of an older build, and for an install-only
  package (`kernel*`, `installonly_limit=3`) install adds side by side, so the
  "rolled back" kernel was still installed and the new one still the boot
  default. Plans 11-16 (all KEV `kernel*`) are the class this would have hit:
  measured on the host, each stores `rollback: []`, `reversible: false` and a
  BARE `dnf -y downgrade kernel*` in `backup[].restore_argv` — plan #10's
  shape, not a pinned rollback. The pinned form is what the recipe produces
  once `_installed_nvr` supplies a version; round 2's rule never ran in
  production, so nothing was pushed anywhere. The objection is about what it
  WOULD have done to the next kernel plan.

  Round 3 (this one): the validator enforces only what the plan lets it
  observe — `true` needs a verified pin, and a package downgrade may not live
  ONLY in `backup[].restore_argv` while `rollback` is empty
  (`downgrade_only_in_backup_restore`, plan #10's actual defect). It never
  judges `false`. The root cause — no installed version in the prompt — is
  fixed by `planner._installed_nvr`, injected by `generate()`; its injection is
  tested by `test_generate_*live_installed_version*` below, which is the part
  round 2 shipped with no test able to fail.

`sentinel/patch/window.py:evaluate` still refuses a self-declared
`reversible: false` plan at first touch, unmodified —
`tests/unit/test_patch_stage1_reversibility_gate.py` is re-run, not
duplicated, to prove this file did not touch it.
"""
from __future__ import annotations

import asyncio
import copy
from types import SimpleNamespace

import pytest

from sentinel.config import Config
from sentinel.patch import planner
from sentinel.patch.validator import validate_plan


def run(c):
    return asyncio.run(c)


# ---------------------------------------------------------------------------
# `_installed_nvr` — the live, read-only fact `os_packages._scan_dnf` never
# records (see its own docstring for why), epoch- and multi-instance-aware the
# same way `checks.py:_check_pkg_version` already is.
#
# Fixtures are what `rpm -q --qf '%{EPOCH}:%{VERSION}-%{RELEASE}\n'` PRINTS on
# the production host (AlmaLinux 9, read 2026-09-29): a package with no epoch
# prints the literal `(none)`, not `0` — a fixture that says `0:` passes
# through a code path rpm never takes.
# ---------------------------------------------------------------------------
class _FakeProc:
    def __init__(self, *, returncode: int | None, stdout: bytes, stderr: bytes = b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.killed = False

    async def communicate(self):
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True


def _rpm_says(monkeypatch, stdout: bytes, *, returncode: int = 0):
    async def _fake_exec(*argv, **kw):
        return _FakeProc(returncode=returncode, stdout=stdout)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)


def test_installed_nvr_asks_for_epoch_version_release_with_a_real_newline(monkeypatch):
    """The bug measured in production: `--qf '%{VERSION}-%{RELEASE}'` has no
    newline and no epoch, so three installed `kernel` instances ran together
    into one unparseable blob and every epoch-carrying package (237 of them,
    including `nginx 2:...` and `openssl 1:...`) silently lost its epoch.
    Falsified by reverting the `--qf` argument to the old string: this
    assertion goes red because the format no longer matches."""
    seen = {}

    async def _fake_exec(*argv, **kw):
        seen["argv"] = argv
        return _FakeProc(returncode=0, stdout=b"(none):5.14.0-687.51.1.el9_8\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    run(planner._installed_nvr("kernel-core"))

    assert seen["argv"] == ("rpm", "-q", "--qf", "%{EPOCH}:%{VERSION}-%{RELEASE}\\n",
                            "kernel-core")


@pytest.mark.parametrize("pkg,printed,expected", [
    # `(none)` epoch: shown WITHOUT a prefix — the form a `dnf downgrade`
    # target and a `pkg_version equals` both use.
    ("kernel-core", b"(none):5.14.0-687.51.1.el9_8\n", "5.14.0-687.51.1.el9_8"),
    # Non-zero epochs are kept. Dropping one (the S1b bug this mirrors in
    # `checks.py`) makes an epoch bump invisible, and the pin would then name
    # a version the host does not have.
    ("nginx", b"2:1.20.1-28.el9_8.6.alma.1\n", "2:1.20.1-28.el9_8.6.alma.1"),
    ("openssl", b"1:3.5.8-1.el9_8\n", "1:3.5.8-1.el9_8"),
    ("microcode_ctl", b"4:20260210-1.20260812.1.el9_8\n", "4:20260210-1.20260812.1.el9_8"),
])
def test_installed_nvr_reproduces_what_rpm_prints_on_the_host(
        monkeypatch, pkg, printed, expected):
    """A regression in epoch handling puts a wrong pin in the prompt, and the
    pin is what the model writes into the rollback. Falsified: making the
    function return the raw first line makes the `(none)` case red."""
    _rpm_says(monkeypatch, printed)

    assert run(planner._installed_nvr(pkg)) == expected


def test_installed_nvr_picks_the_newest_of_multiple_installed_instances(monkeypatch):
    """`kernel` and its `kernel-*` siblings are installed THREE TIMES each at
    once, by design (`installonly_limit=3`). `rpm -q` prints them in database
    order, not version order — reading only the first is not necessarily the
    newest; `_best_installed` (reused, not re-derived) compares all of them."""
    _rpm_says(monkeypatch, (
        b"(none):5.14.0-687.42.1.el9_8\n"
        b"(none):5.14.0-687.51.1.el9_8\n"
        b"(none):5.14.0-687.46.1.el9_8\n"))

    assert run(planner._installed_nvr("kernel-core")) == "5.14.0-687.51.1.el9_8"


def test_installed_nvr_returns_none_when_rpm_says_not_installed(monkeypatch):
    _rpm_says(monkeypatch, b"", returncode=1)

    assert run(planner._installed_nvr("nu-exista")) is None


def test_installed_nvr_returns_none_when_rpm_is_not_on_this_host(monkeypatch):
    """The sandbox this suite runs in has no `rpm` at all — this is not a
    hypothetical, it is what every OTHER test in this file relies on NOT
    crashing generate()."""
    async def _fake_exec(*argv, **kw):
        raise FileNotFoundError("rpm")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    assert run(planner._installed_nvr("nginx")) is None


def test_installed_nvr_returns_none_on_timeout_not_a_hang(monkeypatch):
    class _HangingProc(_FakeProc):
        async def communicate(self):
            raise asyncio.TimeoutError

    async def _fake_exec(*argv, **kw):
        return _HangingProc(returncode=0, stdout=b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    assert run(planner._installed_nvr("nginx")) is None


def test_installed_nvr_returns_none_when_killed_by_a_signal(monkeypatch, caplog):
    """A negative `returncode` means the subprocess was killed by a signal
    (e.g. seccomp SIGSYS under a hardened unit), not that rpm itself declined
    the query — a sandbox problem, not a missing package, and the two must
    not be folded into the same silent `None`. Falsified: deleting the
    `returncode < 0` branch (folding it into the plain "not installed" log
    line) makes the `reason` assertion below red while the return value
    stays `None` — proving the log distinction is a real, separate check,
    not incidental to the return value."""
    async def _fake_exec(*argv, **kw):
        return _FakeProc(returncode=-31, stdout=b"", stderr=b"Bad system call")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    with caplog.at_level("ERROR", logger="sentinel.patch.planner"):
        result = run(planner._installed_nvr("nginx"))

    assert result is None
    assert any(getattr(rec, "reason", None) == "killed" for rec in caplog.records), (
        "a package killed by a signal was logged the same way as one simply "
        "not installed — 'unknown' and 'not there' must stay distinguishable")


def test_installed_nvr_returns_none_when_rpm_exits_zero_with_no_output(monkeypatch, caplog):
    """Defensive: `rpm -q` exiting 0 with empty stdout should never happen,
    but treating it as a version (`""`) would let an empty string reach
    `_parse_rpm_evr` and be stored as a rollback pin nobody verified."""
    _rpm_says(monkeypatch, b"")

    with caplog.at_level("WARNING", logger="sentinel.patch.planner"):
        result = run(planner._installed_nvr("nginx"))

    assert result is None
    assert any(getattr(rec, "reason", None) == "empty_output" for rec in caplog.records)


# ---------------------------------------------------------------------------
# `generate()` end to end, through the REAL `validate_plan` — not mocked, so
# a mutation that reintroduces the overwrite is caught by the same rules a
# real plan would be held to.
# ---------------------------------------------------------------------------
_KERNEL_V = "5.14.0-687.51.1.el9_8"


def _wire(monkeypatch, *, ctx: dict, tool_input: dict, captured: list,
          nvr_calls: list | None = None, nvr_answer: str | None = None,
          prompts: list | None = None):
    """Wire `generate()` to fakes. `nvr_calls` records every package the live
    lookup was ASKED about (so a test can assert it was, or was not, made);
    `nvr_answer` is what it says; `prompts` records each `user` prompt the
    model was shown."""
    async def _context(db, finding_id):
        return ctx

    async def _allowed(db, cfg):
        return True, ""

    async def _record(*a, **kw):
        return None

    async def _call(api_key, **kw):
        if prompts is not None:
            prompts.append(kw["user"])
        return SimpleNamespace(
            ok=True, error=None, tool_input=copy.deepcopy(tool_input),
            usage=SimpleNamespace(input_tokens=1, output_tokens=1, cached_tokens=0))

    async def _store_plan(db, **kw):
        captured.append(kw)
        return 77

    async def _nvr(pkg):
        if nvr_calls is not None:
            nvr_calls.append(pkg)
        return nvr_answer

    monkeypatch.setattr(planner, "_context", _context)
    monkeypatch.setattr(planner.budget, "allowed", _allowed)
    monkeypatch.setattr(planner.budget, "record", _record)
    monkeypatch.setattr(planner, "call_structured", _call)
    monkeypatch.setattr(planner.repo, "store_plan", _store_plan)
    # The live `rpm -q` must never run for real here: this machine has no rpm,
    # so an unpatched lookup answers `None` and hides whether `generate()`
    # ever asked. A recorder that answers what the test says is the only way
    # the injection can be seen to happen or not to happen.
    monkeypatch.setattr(planner, "_installed_nvr", _nvr)


def _rhel_cfg() -> Config:
    cfg = Config()
    cfg.platform.family = "rhel"
    return cfg


def _debian_cfg() -> Config:
    cfg = Config()
    cfg.platform.family = "debian"
    return cfg


def _nginx_ctx(**over) -> dict:
    ctx = {"id": 1, "cve": "CVE-2026-9999", "package": "nginx",
           "ecosystem": "rpm", "installed_version": "1.20.1-14.el9",
           "fixed_version": "1.20.1-16.el9_5", "severity": "high",
           "cvss": None, "epss": None, "kev": False,
           "protected": False, "asset_id": 3, "priority": 60}
    ctx.update(over)
    return ctx


def _kernel_plan(good_plan: dict, *, reversible: bool) -> dict:
    """A kernel plan as the recipe WOULD write it once a version exists.

    Deliberately not the shape plans 11-16 actually have on the host — those
    store an empty `rollback` and a bare downgrade in `backup[].restore_argv`.
    This is the next one: `kernel-core`, KEV, a version-pinned `dnf downgrade`
    in `rollback`, and a reboot. That is the case round 2 would have refused.
    """
    plan = copy.deepcopy(good_plan)
    plan["target"]["asset_name"] = "kernel-core"
    plan["vulnerabilities"][0].update(package="kernel-core", current=_KERNEL_V)
    plan["preflight"][0]["check"].update(name="kernel-core", equals=_KERNEL_V)
    plan["apply"] = [{**good_plan["apply"][0], "argv": ["dnf", "-y", "update", "kernel-core"]}]
    pin = ["dnf", "-y", "downgrade", f"kernel-core-{_KERNEL_V}"]
    plan["backup"][0].update(source="kernel-core", restore_argv=pin)
    plan["rollback"][0]["argv"] = pin
    plan["risk"].update(requires_reboot=True, reversible=reversible)
    return plan


# -- F2: the live lookup is actually injected, and only where it should be ---
def test_generate_hands_the_live_installed_version_to_the_model_and_the_plan(
        monkeypatch, good_plan):
    """The root cause of plan #10: `findings.installed_version` is null for
    every rpm finding, so the model was told not to guess a rollback pin and
    had none. `generate()` fills it from `_installed_nvr`. Without this test
    the three lines that do so could be replaced by `pass` and every other
    test in the suite stayed green (measured: 167 passed) — because every
    test that reached `generate()` forced the lookup to `None` or returned
    before it.

    Falsified: replacing the `ctx = {**ctx, "installed_version": live_nvr}`
    injection with `pass` makes all three assertions red."""
    ctx = _nginx_ctx(package="kernel-core", installed_version=None,
                     fixed_version="5.14.0-687.52.1.el9_8", kev=True)
    captured: list = []
    calls: list = []
    prompts: list = []
    _wire(monkeypatch, ctx=ctx, tool_input=_kernel_plan(good_plan, reversible=False),
          captured=captured, nvr_calls=calls, nvr_answer=_KERNEL_V, prompts=prompts)

    run(planner.generate(object(), _rhel_cfg(), "sk-test", 41655))

    assert calls == ["kernel-core"], "the live lookup was never asked"
    assert f"versiune instalată: {_KERNEL_V}" in prompts[0]
    assert (f'["dnf", "-y", "downgrade", "kernel-core-{_KERNEL_V}"]' in prompts[0]), (
        "the recipe was not given the pinned rollback the version makes possible")
    assert captured[0]["plan"]["vulnerabilities"][0]["current"] == _KERNEL_V, (
        "the stored plan does not carry the installed version it was drafted against")


def test_generate_keeps_a_nonzero_epoch_in_what_the_model_is_shown(
        monkeypatch, good_plan):
    """A `nginx` pin without its `2:` names a build the host does not have;
    the rollback runs on the worst day. The prompt must carry the epoch
    exactly as `_installed_nvr` returned it."""
    live = "2:1.20.1-28.el9_8.6.alma.1"
    captured: list = []
    prompts: list = []
    _wire(monkeypatch, ctx=_nginx_ctx(installed_version=None),
          tool_input=good_plan, captured=captured, nvr_answer=live, prompts=prompts)

    run(planner.generate(object(), _rhel_cfg(), "sk-test", 9002))

    assert f"versiune instalată: {live}" in prompts[0]
    assert captured[0]["plan"]["vulnerabilities"][0]["current"] == live


def test_generate_says_unknown_when_the_live_lookup_cannot_answer(
        monkeypatch, good_plan):
    """`None` means "cannot know", never "fine": the prompt must say the
    version is unknown and must NOT contain a pinned rollback the model could
    copy. Falsified: substituting a default version for `None` makes the
    `necunoscută` assertion red."""
    captured: list = []
    prompts: list = []
    _wire(monkeypatch, ctx=_nginx_ctx(installed_version=None),
          tool_input=good_plan, captured=captured, nvr_answer=None, prompts=prompts)

    run(planner.generate(object(), _rhel_cfg(), "sk-test", 9002))

    assert "versiune instalată: necunoscută" in prompts[0]
    assert "- rollback: NU se poate fixa pe o versiune" in prompts[0]
    assert '"downgrade"' not in prompts[0].split("Comenzile exacte", 1)[1]


@pytest.mark.parametrize("label,cfg_factory,ctx_over", [
    # Debian: `rpm` is not there and `findings.installed_version` comes from
    # the scanner. Asking would run `rpm -q` on a host that has none.
    ("deb_finding_on_debian", _debian_cfg,
     {"ecosystem": "deb", "installed_version": None}),
    # The family gate on its own: an rpm-ecosystem finding on a debian host
    # (unreachable through `unplannable_reason`, but `generate()` is the last
    # gate before a subprocess and must not lean on a caller having asked).
    ("rpm_finding_on_debian", _debian_cfg,
     {"ecosystem": "rpm", "installed_version": None}),
    # A non-rpm finding on an rhel host (npm, from a container image): not a
    # host package, `rpm -q` would say "not installed" and mean nothing.
    ("npm_finding_on_rhel", _rhel_cfg,
     {"ecosystem": "npm", "installed_version": None}),
    # The finding already carries a version: the database's value is the
    # fact the plan is ABOUT, a live read must not replace it.
    ("finding_with_a_version", _rhel_cfg,
     {"installed_version": "1.20.1-14.el9"}),
])
def test_generate_does_not_query_rpm_when_it_should_not(
        monkeypatch, good_plan, label, cfg_factory, ctx_over):
    """The lookup is a subprocess on a production host, run under a sandbox
    with a memory cap. It must run for exactly one case — an rhel host, an rpm
    finding, no version — and for none of these. Falsified: dropping the
    family test makes the deb case red; dropping the ecosystem test, the npm
    case; dropping `not ctx.get("installed_version")`, the third."""
    captured: list = []
    calls: list = []
    prompts: list = []
    _wire(monkeypatch, ctx=_nginx_ctx(**ctx_over), tool_input=good_plan,
          captured=captured, nvr_calls=calls,
          nvr_answer="9.9.9-9.el9", prompts=prompts)

    run(planner.generate(object(), cfg_factory(), "sk-test", 9002))

    assert calls == [], f"{label}: rpm was queried"
    assert "9.9.9-9.el9" not in prompts[0], (
        f"{label}: a live value reached the prompt anyway")


def test_generate_never_overwrites_the_models_declaration(monkeypatch, good_plan):
    """`good_plan` declares `risk.reversible: true` with a fully pinned,
    preflight-verified `dnf downgrade` rollback — already self-consistent.
    `generate()` must store exactly that, not recompute it."""
    plan = copy.deepcopy(good_plan)
    captured: list = []
    _wire(monkeypatch, ctx=_nginx_ctx(), tool_input=plan, captured=captured)

    _, status = run(planner.generate(object(), _rhel_cfg(), "sk-test", 9002))

    assert status == "validated", captured
    stored = captured[0]["plan"]
    assert stored["risk"]["reversible"] is True
    assert stored["rollback"] == plan["rollback"]


# -- F1: an honest `false` is never pushed toward `true` --------------------
def test_an_honest_false_with_a_pinned_rollback_is_valid_and_stored_as_false(
        monkeypatch, good_plan):
    """The kernel case round 2 got wrong. The model wrote the recipe's pinned
    `dnf downgrade kernel-core-<installed>` and said `reversible: false`
    because `kernel` is install-only: the downgrade removes nothing, the new
    kernel stays the boot default. That is TRUE, and the validator has no way
    to know it is not — so it must not refuse it, and above all must not tell
    the model to write `true`, which would put a no-op rollback past
    `window.py`'s gate.

    Falsified: restoring round 2's `_validate_reversibility_declaration` (a
    hard error when `false` meets a fully pinned rollback) makes `status`
    `rejected_invalid` and this red."""
    plan = _kernel_plan(good_plan, reversible=False)
    ctx = _nginx_ctx(package="kernel-core", installed_version=_KERNEL_V,
                     fixed_version="5.14.0-687.52.1.el9_8", kev=True)
    captured: list = []
    _wire(monkeypatch, ctx=ctx, tool_input=plan, captured=captured)

    _, status = run(planner.generate(object(), _rhel_cfg(), "sk-test", 41655))

    assert status == "validated", captured
    assert captured[0]["plan"]["risk"]["reversible"] is False
    result = validate_plan(plan, platform_family="rhel",
                           finding={"finding_id": 402, "cve": "CVE-2026-9999",
                                    "package": "kernel-core"})
    assert result.valid, [e.as_dict() for e in result.errors]
    assert "rollback_on_irreversible" in {w.code for w in result.warnings}, (
        "the plan admits the rollback may not restore; that admission must stay "
        "visible as the warning, not vanish")


def test_a_true_with_a_pinned_rollback_is_still_valid(good_plan):
    """The direction the validator CAN observe, kept: `true` with a rollback
    that pins the preflight-verified version passes. Control for the test
    above — a validator that refused everything would satisfy it too, so this
    shows the refusal is not blanket."""
    plan = _kernel_plan(good_plan, reversible=True)

    result = validate_plan(plan, platform_family="rhel")

    assert result.valid, [e.as_dict() for e in result.errors]


def test_true_with_no_rollback_is_still_refused(good_plan):
    """`true` is the direction the validator holds to evidence
    (`rollback_required`): claiming reversibility with nothing that reverses."""
    plan = _kernel_plan(good_plan, reversible=True)
    plan["rollback"] = []
    plan["backup"][0]["restore_argv"] = ["tar", "--zstd", "-xf", "{artifact}", "-C", "/"]

    result = validate_plan(plan, platform_family="rhel")

    assert "rollback_required" in {e.code for e in result.errors}


def test_a_dnf_pin_that_merely_starts_with_the_verified_version_is_a_mismatch(good_plan):
    """`14.el9` vs `14.el9_5`: the second string STARTS WITH the first and is
    a different build. A pin accepted on a prefix names a version the
    preflight never verified, in the section that runs when something has
    already gone wrong. Nothing else in the suite distinguishes an exact
    match from a prefix match in `_validate_dnf_pin`.

    Falsified: changing `target == f"{name}-{version}"` there to
    `target.startswith(...)` makes this red."""
    plan = copy.deepcopy(good_plan)
    plan["rollback"][0]["argv"] = ["dnf", "-y", "downgrade", "nginx-1.20.1-14.el9_5"]

    result = validate_plan(plan, platform_family="rhel")

    assert "rollback_pin_mismatch" in {e.code for e in result.errors}


# -- Plan #10's actual defect: a downgrade only in backup.restore_argv -------
def _plan_10_shape(good_plan: dict, *, reversible: bool) -> dict:
    """Measured: `restore_argv` `["dnf","-y","downgrade","webkit2gtk3-jsc"]`,
    `rollback` `[]`, `reversible` false."""
    plan = copy.deepcopy(good_plan)
    plan["target"]["asset_name"] = "webkit2gtk3-jsc"
    plan["vulnerabilities"][0].update(package="webkit2gtk3-jsc", current=None)
    plan["preflight"][0]["check"] = {"kind": "disk_free", "path": "/var/backups/sentinel",
                                     "min_bytes": 1000000}
    plan["preflight"][2:3] = []
    plan["backup"] = [{"id": "bk1", "desc_ro": "starea rpm curentă", "kind": "rpm_state",
                       "source": "webkit2gtk3-jsc", "estimated_size_mb": 1,
                       "restore_argv": ["dnf", "-y", "downgrade", "webkit2gtk3-jsc"]}]
    plan["apply"] = [{**good_plan["apply"][0], "argv": ["dnf", "-y", "update", "webkit2gtk3-jsc"]}]
    plan["rollback"] = []
    plan["risk"]["reversible"] = reversible
    return plan


@pytest.mark.parametrize("reversible", [False, True])
def test_a_downgrade_only_in_backup_restore_argv_is_refused_whatever_reversible_says(
        good_plan, reversible):
    """Plan #10, the operator's incident: the undo the plan wrote sat in
    `backup[].restore_argv`, which nothing runs automatically, while `rollback`
    was empty — so the rollback phase did nothing and `window.py` refused the
    plan forever for being irreversible. The defect is the section the undo is
    in, decidable from the plan without judging `reversible`: it is refused
    under BOTH declarations, and the error must not tell the model what to
    declare.

    Falsified: deleting `_validate_downgrade_lives_in_rollback`'s call in
    `_validate_coupling` makes the `False` case red (the `True` case is also
    caught by `rollback_required`, which is why it asserts the new code by
    name)."""
    plan = _plan_10_shape(good_plan, reversible=reversible)

    result = validate_plan(plan, platform_family="rhel")

    errs = {e.code: e for e in result.errors}
    assert "downgrade_only_in_backup_restore" in errs, [e.as_dict() for e in result.errors]
    assert errs["downgrade_only_in_backup_restore"].path == "$.backup[id=bk1].restore_argv"
    message = errs["downgrade_only_in_backup_restore"].message
    assert "reversible:true" not in message and "reversible:false" not in message
    assert "set reversible" not in message.lower(), (
        "the shape error must not steer the model toward either declaration")


def test_the_apt_form_of_the_same_defect_is_refused_too(debian_plan):
    """Debian has no `apt-get downgrade`; the undo is `install
    --allow-downgrades pkg=version`. The same misplacement, the same refusal —
    a rule that only knew `dnf` would leave the deb host exactly where plan #10
    left the rpm one."""
    plan = copy.deepcopy(debian_plan)
    plan["rollback"] = []
    plan["backup"][0]["restore_argv"] = ["apt-get", "-y", "install",
                                         "--allow-downgrades", "polkitd=0.105-1"]

    result = validate_plan(plan, platform_family="debian")

    assert "downgrade_only_in_backup_restore" in {e.code for e in result.errors}


def test_a_downgrade_in_restore_argv_is_fine_when_the_rollback_carries_one(good_plan):
    """Control: `good_plan` has the downgrade in BOTH `restore_argv` and
    `rollback` and must stay valid — otherwise the rule refuses every plan
    the recipe produces and the operator simply never gets one."""
    result = validate_plan(copy.deepcopy(good_plan), platform_family="rhel")

    assert result.valid, [e.as_dict() for e in result.errors]


def test_a_restore_argv_that_is_not_a_downgrade_is_not_flagged(good_plan):
    """The rule reads what `restore_argv` DOES (a package downgrade), not that
    `rollback` is empty: a config-file backup restored with `tar` and no
    package rollback is an honest irreversible-by-Sentinel plan."""
    plan = copy.deepcopy(good_plan)
    plan["rollback"] = []
    plan["risk"]["reversible"] = False
    plan["backup"] = [good_plan["backup"][1]]

    result = validate_plan(plan, platform_family="rhel")

    assert result.valid, [e.as_dict() for e in result.errors]
    assert result.summary["reversible"] is False


def test_generate_rejects_plan_10_and_stores_the_refusal(monkeypatch, good_plan):
    """End to end: the mocked model returns plan #10's shape both times, so
    the retry loop ends `rejected_invalid` with the new code recorded — an
    invalid plan stays visible as evidence about the model rather than being
    silently repaired or approved."""
    plan = _plan_10_shape(good_plan, reversible=False)
    ctx = _nginx_ctx(id=10, cve="CVE-2026-3909", package="webkit2gtk3-jsc",
                     installed_version=None, fixed_version="2.54.0-1.el9", kev=True)
    captured: list = []
    _wire(monkeypatch, ctx=ctx, tool_input=plan, captured=captured)

    _, status = run(planner.generate(object(), _rhel_cfg(), "sk-test", 10))

    assert status == "rejected_invalid", captured
    assert "downgrade_only_in_backup_restore" in {
        e["code"] for e in captured[0]["validation_errors"]}


def test_no_provable_rollback_stays_irreversible_and_is_stored_as_drafted(
        monkeypatch, good_plan):
    """Plan #10 corrected the way the recipe wants when no version can be
    proven: no rollback, no downgrade anywhere, `false`, and a
    `restore_instructions_ro` the model wrote itself. `generate()` must store
    it exactly — no marker appended, nothing flipped."""
    plan = copy.deepcopy(good_plan)
    plan["rollback"] = []
    plan["risk"]["reversible"] = False
    plan["backup"] = [good_plan["backup"][1]]
    plan["restore_instructions_ro"] = (
        "Nu există azi o cale automată de revenire pentru acest pachet.")
    captured: list = []
    _wire(monkeypatch, ctx=_nginx_ctx(installed_version=None), tool_input=plan,
          captured=captured)

    _, status = run(planner.generate(object(), _rhel_cfg(), "sk-test", 10))

    assert status == "validated", captured
    stored = captured[0]["plan"]
    assert stored["risk"]["reversible"] is False
    assert stored["restore_instructions_ro"] == plan["restore_instructions_ro"]


# ---------------------------------------------------------------------------
# The six counterexamples that sank the first fix, end to end. With round 2's
# hard error gone, NOTHING in the validator or the planner interprets these
# rollbacks: what is asserted is that no code path turns the model's `false`
# into `true` — in the validator's summary or in what `generate()` stores.
# ---------------------------------------------------------------------------
def _false_with(good_plan: dict, rollback_argv: list[str]) -> dict:
    plan = copy.deepcopy(good_plan)
    plan["risk"]["reversible"] = False
    plan["rollback"] = [{**good_plan["rollback"][0], "argv": rollback_argv}]
    return plan


# C and G were `dnf clean all` and `dnf makecache`. Those cannot run in the executor's
# sandbox (policy.sandbox_refusal: they exit 1 with "Read-only file system"), so a plan that
# carries one is refused as `step_cannot_run` before the question below is ever asked
# (tests/unit/test_patch_plan_can_run.py). They are replaced by rollbacks that DO run and
# still restore nothing - a query and a status - so the property stays tested: no code path
# turns the model's `false` into `true`.
@pytest.mark.parametrize("label,rollback_argv", [
    ("A_restart_only", ["systemctl", "restart", "nginx.service"]),
    ("B_reinstall", ["dnf", "-y", "reinstall", "nginx"]),
    ("C_rpm_query", ["rpm", "-q", "nginx"]),
    ("D_re_apply", ["dnf", "-y", "update", "nginx"]),
    ("G_status_only", ["systemctl", "status", "nginx.service"]),
])
def test_the_counterexamples_that_sank_the_first_fix_stay_false(
        monkeypatch, good_plan, label, rollback_argv):
    """A, B, C, D, G: schema-valid rollbacks that restore nothing. Round 1's
    flip (`bool(plan['rollback'])`) said `true` for all five, turning a
    refusal the operator could see into a silent approval. The plan must stay
    valid AND stay `reversible: false`, in the validator's summary and in the
    stored plan.

    Falsified: reintroducing the overwrite in `generate()`
    (`plan["risk"]["reversible"] = bool(plan.get("rollback"))` before the
    store) makes the stored assertion red for all five."""
    plan = _false_with(good_plan, rollback_argv)

    result = validate_plan(plan, platform_family="rhel")
    assert result.valid, [e.as_dict() for e in result.errors]
    assert result.summary["reversible"] is False, (
        f"case {label}: a rollback that restores nothing made the plan look reversible")

    captured: list = []
    _wire(monkeypatch, ctx=_nginx_ctx(), tool_input=plan, captured=captured)
    _, status = run(planner.generate(object(), _rhel_cfg(), "sk-test", 9002))
    assert status == "validated", captured
    assert captured[0]["plan"]["risk"]["reversible"] is False, (
        f"case {label}: generate() flipped the model's declaration")


def test_the_sixth_counterexample_a_partial_pin_stays_false(monkeypatch, good_plan):
    """E: the apply step updates two packages (nginx and nginx-filesystem), the
    rollback pins only nginx. Nothing here upgrades that `false`: the model
    said the plan cannot fully undo itself, and it is right."""
    plan = copy.deepcopy(good_plan)
    plan["risk"]["reversible"] = False
    plan["apply"] = [
        good_plan["apply"][0],
        {**good_plan["apply"][0], "id": "ap1b",
         "desc_ro": "Actualizează pachetul nginx-filesystem",
         "argv": ["dnf", "-y", "update", "nginx-filesystem"]},
        *good_plan["apply"][1:],
    ]
    captured: list = []
    _wire(monkeypatch, ctx=_nginx_ctx(), tool_input=plan, captured=captured)

    _, status = run(planner.generate(object(), _rhel_cfg(), "sk-test", 9002))

    assert status == "validated", captured
    assert captured[0]["plan"]["risk"]["reversible"] is False
