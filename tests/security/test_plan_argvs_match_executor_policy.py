"""The validator and the root executor must not have two opinions about argv.

The failure this file prevents, measured on 18 September 2026: the operator
gets a patch plan on Telegram, reads it, approves it — and the apply dies at
step 1 because the command the validator blessed is one `executor/policy.py`
refuses outright. On a Debian host that was EVERY plan
(`apt-get -y install --only-upgrade <pkg>`), and on the rhel side the same
class of bug sat in the project's own "known-good" fixture
(`["systemctl", "reload", "nginx"]` — the executor requires a full unit name).
A plan that dies mid-flight is worse than one that was never offered: the
package may already be updated, so the operator is now in a half-applied state
they did not choose.

Three rounds passed with that hole open because nothing ever ran a plan's
commands through the thing that actually decides. That is what this file does.

Round 4: it did it for four argv shapes, not all of them. `checks.py` builds
an argv for SIX check kinds and its own module docstring said "only the
`command` kind reaches the executor" — so a `systemd` health check on
`dbus.service`, a `file_exists` on `/etc/shadow` and a `pkg_version` whose
package name contains `passwd` all validated clean and were refused at run
time. For a health check that refusal lands after the apply step, so a patch
that worked gets rolled back. The coverage at the bottom of this file is
generated from `CHECK_KINDS` for that reason: a hand-written list of shapes is
what went stale the first time.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import policy
from sentinel.patch.validator import CHECK_KINDS as _ALL_CHECK_KINDS
from sentinel.patch.validator import validate_plan

pytestmark = pytest.mark.security

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _plan_argvs(plan: dict, family: str = "rhel") -> list[tuple[str, list[str]]]:
    """Every argv in a plan that the executor will be asked to run.

    An INDEPENDENT oracle, written out here on purpose: reusing
    `validator._iter_plan_argvs` or `checks.argv_for` would make this test
    agree with the code by construction, and those are the two sides being
    compared. The literal shapes are apply/rollback `argv` and a backup's
    `restore_argv`; the rest are the commands `sentinel/patch/checks.py`
    builds from a structured check and sends down the same
    `patch_step_exec` path.

    A kind added to `argv_for` and not added here makes the set comparison
    in `test_every_built_argv_reaches_the_executors_own_check` fail with an
    extra entry — which is the right way to find out, rather than this
    oracle quietly covering less than the code does.
    """
    out: list[tuple[str, list[str]]] = []
    for section in ("apply", "rollback"):
        for step in plan.get(section) or []:
            out.append((f"{section}[{step.get('id')}]", step["argv"]))
    for b in plan.get("backup") or []:
        out.append((f"backup[{b.get('id')}].restore_argv", b["restore_argv"]))
    for section in ("preflight", "health_check", "post_verification"):
        for item in plan.get(section) or []:
            check = item.get("check") or {}
            kind = check.get("kind")
            where = f"{section}[{item.get('id')}].argv"
            if kind == "command":
                out.append((where, check["argv"]))
            elif kind == "systemd":
                out.append((where, ["systemctl", "is-active", str(check["unit"])]))
            elif kind in ("file_exists", "file_absent"):
                out.append((where, ["test", "-e", str(check["path"])]))
            elif kind == "file_sha256":
                out.append((where, ["sha256sum", str(check["path"])]))
            elif kind == "pkg_version" and family == "rhel":
                out.append((where, ["rpm", "-q", "--qf",
                                    r"%{EPOCH}:%{VERSION}-%{RELEASE}\n",
                                    str(check["name"])]))
            elif kind == "pkg_version" and family == "debian":
                out.append((where, ["dpkg-query", "-W", "-f", r"${Version}\n",
                                    str(check["name"])]))
    return out


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


GOOD_PLAN = _load("good_plan.json")
DEBIAN_PLAN = _load("debian_plan.json")

_CASES = [
    pytest.param(argv, id=f"{fixture}:{where}")
    for fixture, plan, family in (("good_plan", GOOD_PLAN, "rhel"),
                                  ("debian_plan", DEBIAN_PLAN, "debian"))
    for where, argv in _plan_argvs(plan, family)
]


def test_the_case_list_is_not_empty():
    """A parametrised list that comes out empty is skipped in silence, and the
    file below would then prove nothing while reporting green — the exact
    pattern CLAUDE.md names. Both fixtures must contribute commands, and both
    must contribute more than the one apply step."""
    assert len(_CASES) >= 15, _CASES
    assert len(_plan_argvs(GOOD_PLAN, "rhel")) >= 9
    assert len(_plan_argvs(DEBIAN_PLAN, "debian")) >= 6


@pytest.mark.parametrize("argv", _CASES)
def test_every_fixture_argv_is_accepted_by_the_root_executor(argv):
    """Each command in the shipped plan fixtures must survive the executor's
    own `check_argv`.

    These fixtures are what the test suite treats as "a valid plan"; if one of
    them contains a command the executor refuses, then "valid" in this
    codebase does not mean "will run", and every test built on the fixture is
    measuring the wrong thing.
    """
    assert policy.check_argv(argv) == argv


def test_validator_refuses_what_the_executor_refuses_apt():
    """The Debian defect itself: `--only-upgrade` is not on the executor's
    apt flag list, so a plan carrying it can never apply. It must be refused
    HERE, before the operator is asked to approve it, rather than at 3am on
    the production host with the package half-updated."""
    plan = copy.deepcopy(DEBIAN_PLAN)
    plan["apply"][0]["argv"] = ["apt-get", "-y", "install", "--only-upgrade", "polkitd"]

    result = validate_plan(plan, platform_family="debian")

    assert not result.valid
    assert "executor_would_refuse" in {e.code for e in result.errors}


def test_validator_refuses_an_unpinned_apt_rollback():
    """`apt-get -y install --allow-downgrades polkitd` — no version — asks apt
    to install ANY older candidate, which is by definition the vulnerable one
    the patch just removed. The executor refuses it; the validator must not
    hand the operator a rollback button that means that."""
    plan = copy.deepcopy(DEBIAN_PLAN)
    plan["rollback"][0]["argv"] = ["apt-get", "-y", "install",
                                   "--allow-downgrades", "polkitd"]

    result = validate_plan(plan, platform_family="debian")

    assert not result.valid
    assert "executor_would_refuse" in {e.code for e in result.errors}


def test_validator_refuses_a_bare_systemd_unit_name():
    """The rhel half of the same drift, and the one that was actually in the
    repository's own good_plan.json: `systemctl reload nginx` is ordinary
    systemd usage and an executor refusal (it requires `nginx.service`). The
    plan would have updated the package and then failed to reload the
    service."""
    plan = copy.deepcopy(GOOD_PLAN)
    plan["apply"][2]["argv"] = ["systemctl", "reload", "nginx"]

    result = validate_plan(plan, platform_family="rhel")

    assert not result.valid
    assert "executor_would_refuse" in {e.code for e in result.errors}


def test_a_refused_command_hidden_in_a_backup_restore_is_still_caught():
    """`restore_argv` is the argv nobody runs until the worst day. A refusal
    there is invisible until a rollback is attempted, which is precisely when
    nothing else is going well."""
    plan = copy.deepcopy(GOOD_PLAN)
    plan["backup"][1]["restore_argv"] = ["apt-get", "-y", "install",
                                         "--only-upgrade", "nginx"]

    result = validate_plan(plan, platform_family=None)

    assert not result.valid
    assert "executor_would_refuse" in {e.code for e in result.errors}


def test_an_unreadable_executor_policy_refuses_the_plan_instead_of_passing_it(
        monkeypatch):
    """On the host the validator imports `executor.policy` from
    /opt/sentinel/lib/executor/ (installed by install.sh step 24). If that
    import fails — a partial deploy, a stale tree — the validator does not
    know whether the plan's commands may run. "Unknown" is refused with the
    reason, not waved through: a monitoring tool that reports "fine" when it
    cannot see is lying.

    It must also not raise: `sentinel/telegram/patch_flow.py` calls this, and
    an exception here would take the alerting channel down with it.
    """
    from sentinel.patch import validator as validator_mod

    monkeypatch.setattr(
        validator_mod, "_executor_policy",
        lambda: (None, "ModuleNotFoundError: No module named 'executor'"))

    result = validate_plan(copy.deepcopy(GOOD_PLAN), platform_family="rhel")

    assert not result.valid
    codes = {e.code for e in result.errors}
    assert "executor_policy_unreadable" in codes
    assert any("executor" in e.message for e in result.errors)


class _SpyPolicy:
    """Stands in for `executor.policy`, recording what it was asked about."""

    PolicyRefusal = policy.PolicyRefusal

    def __init__(self, *, verdict=None):
        self.seen: list[list[str]] = []
        self._verdict = verdict

    def check_argv(self, argv):
        self.seen.append(list(argv))
        if self._verdict is not None:
            self._verdict(argv)
        return list(argv)


def test_all_four_argv_shapes_reach_the_executors_own_check(monkeypatch):
    """Not "the validator calls check_argv somewhere" — that a command in
    EACH of the four places a plan can hide one is put to the executor.

    A version of this that only walked `apply` would leave a refused command
    in a rollback, a backup restore or a `command` check waved through, and
    each of those is discovered at the worst possible moment: mid-rollback,
    mid-recovery, or in the preflight of a change the operator is watching.
    """
    from sentinel.patch import validator as validator_mod

    plan = copy.deepcopy(GOOD_PLAN)
    plan["preflight"].append({
        "id": "pf_cmd", "desc_ro": "verificare prin comandă", "blocking": False,
        "check": {"kind": "command", "argv": ["nginx", "-t"]},
    })
    spy = _SpyPolicy()
    monkeypatch.setattr(validator_mod, "_executor_policy", lambda: (spy, None))

    result = validate_plan(plan, platform_family="rhel")

    assert result.valid, [e.as_dict() for e in result.errors]
    assert ["dnf", "-y", "update", "nginx"] in spy.seen            # apply
    assert ["systemctl", "restart", "nginx.service"] in spy.seen   # rollback
    assert ["tar", "--zstd", "-xf", "{artifact}", "-C", "/"] in spy.seen  # restore
    assert ["nginx", "-t"] in spy.seen                             # command check
    assert len(spy.seen) == len(_plan_argvs(plan))


def test_the_verdict_comes_from_the_executor_not_from_a_local_copy(monkeypatch):
    """One source of truth, proved by behaviour rather than by reading the
    file: with the executor's grammar replaced by one that permits
    everything, the plan the real grammar rejects must now validate.

    If the validator kept its own copy of the apt rules, this test would stay
    red — and a copy is exactly what drifted for three rounds. It is also the
    test that fails if someone "helpfully" re-adds a local flag list as a
    belt-and-braces measure: two authorities is the bug, not the fix.
    """
    from sentinel.patch import validator as validator_mod

    plan = copy.deepcopy(DEBIAN_PLAN)
    plan["apply"][0]["argv"] = ["apt-get", "-y", "install", "--only-upgrade", "polkitd"]

    assert not validate_plan(plan, platform_family="debian").valid

    monkeypatch.setattr(validator_mod, "_executor_policy",
                        lambda: (_SpyPolicy(), None))
    result = validate_plan(plan, platform_family="debian")

    assert result.valid, [e.as_dict() for e in result.errors]


# ---------------------------------------------------------------------------
# The import has to work in the DEPLOYED layout, not just under conftest
# ---------------------------------------------------------------------------
# `tests/conftest.py` puts `<repo>/executor` on `sys.path` so the executor's
# own hostile-input tests can `import policy`. Nothing on the production host
# does that: the units run with `PYTHONPATH=/opt/sentinel/lib`, and the root
# daemon's copy lives in /opt/sentinel/libexec, which is NOT on that path. A
# validator that only worked because of the test harness would refuse every
# plan in production while every test stayed green.
def test_the_validator_reaches_the_executor_policy_without_the_test_harness(tmp_path):
    """Runs in a fresh interpreter whose only import root is the repository
    root — the same shape as /opt/sentinel/lib, which holds `sentinel/` and
    (after install.sh step 24) `executor/` side by side, and nothing else.

    Checks the EFFECT: a plan validates clean. If the import failed, the
    validator would report `executor_policy_unreadable` and every patch plan
    on the host would be refused — which is exactly the failure this proves
    is absent, rather than asserting that an import statement is present.
    """
    import subprocess
    import sys

    script = tmp_path / "probe.py"
    script.write_text(
        "import json, sys\n"
        "from sentinel.patch.validator import validate_plan\n"
        f"plan = json.load(open(r'{(FIXTURES / 'good_plan.json')}', encoding='utf-8'))\n"
        "res = validate_plan(plan, platform_family='rhel')\n"
        "print(json.dumps([e.code for e in res.errors]))\n"
        "assert 'executor' not in ' '.join(sys.modules) or True\n",
        encoding="utf-8")

    repo_root = str(FIXTURES.parent.parent)
    proc = subprocess.run(
        [sys.executable, "-B", str(script)],
        cwd=str(tmp_path), capture_output=True, text=True,
        env={"PYTHONPATH": repo_root, "PYTHONDONTWRITEBYTECODE": "1",
             "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
             "PATH": __import__("os").environ.get("PATH", "")})

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip().endswith("[]"), (
        "the plan did not validate cleanly outside the test harness: "
        + proc.stdout + proc.stderr)


def test_the_installer_puts_policy_where_the_validator_imports_it():
    """`install.sh` step 24 must install `executor/policy.py` a second time
    under `${SENTINEL_PREFIX}/lib/executor/`, and must then PROVE it is
    importable as the sentinel user rather than assume it.

    Without the copy, a deploy of this change leaves the validator unable to
    load the grammar, and every patch plan — rhel and debian alike — is
    refused with `executor_policy_unreadable`. Without the import check, a
    wrong path or a permissions slip would be discovered hours later, on
    Telegram, instead of at deploy time.
    """
    installer = (FIXTURES.parent.parent / "deploy" / "install.sh").read_text(
        encoding="utf-8")
    assert '"${SENTINEL_PREFIX}/lib/executor/policy.py"' in installer, (
        "install.sh no longer installs the validator's copy of the executor "
        "policy")
    assert "import executor.policy" in installer, (
        "install.sh no longer verifies that the copy it just wrote can "
        "actually be imported — a file on disk is not proof it loads")
    assert 'rm -rf "${SENTINEL_PREFIX}/lib/sentinel" "${SENTINEL_PREFIX}/lib/executor"' \
        in installer, (
        "the stale lib/executor tree is no longer cleared before the copy; a "
        "leftover __init__.py or .pyc there would shadow the fresh file")


# ---------------------------------------------------------------------------
# Coverage derived from the kind list, not from a hand-written list of shapes
# ---------------------------------------------------------------------------
# The round-3 version of this file checked four argv shapes, because
# `checks.py`'s module docstring said only the `command` kind reached the
# executor. Six kinds do. The cost of that sentence, measured on the Ubuntu
# host: stored plan #1 is `validated` with health checks on `dbus.service`,
# an `UNCONTROLLABLE_UNITS` entry — the executor refuses the argv, and because
# `checks.evaluate` returns a failed check rather than raising, the refusal
# lands AFTER the apply step, so a successful patch is rolled back.
#
# A fifth hand-written enumeration would have gone stale the same way, so the
# coverage below is generated FROM `CHECK_KINDS`. A kind added to the
# vocabulary, or taught a new argv, is covered the day it is added or this
# test fails.
_SAMPLE_FIELD_VALUES: dict[str, object] = {
    "url": "https://127.0.0.1/healthz",
    "expect_status": 200,
    "host": "127.0.0.1",
    "port": 443,
    "unit": "nginx.service",
    "expect_state": "active",
    "container": "app",
    "name": "nginx",
    "path": "/etc/nginx/nginx.conf",
    "sha256": "0" * 64,
    "min_bytes": 1,
    "asset_id": 3,
    "argv": ["nginx", "-t"],
}


def _sample_check(kind: str) -> dict:
    """A minimal well-formed check of `kind`, built from the validator's own
    `CHECK_REQUIRED_FIELDS`. A new kind whose fields are not in the table
    above fails loudly here rather than being skipped."""
    from sentinel.patch.validator import CHECK_REQUIRED_FIELDS

    check: dict = {"kind": kind}
    for field in CHECK_REQUIRED_FIELDS.get(kind, ()):
        if field not in _SAMPLE_FIELD_VALUES:
            pytest.fail(
                f"check kind {kind!r} requires field {field!r}, which this test "
                "has no sample value for — add one, or this kind silently stops "
                "being covered")
        check[field] = _SAMPLE_FIELD_VALUES[field]
    if kind == "pkg_version":
        check["equals"] = "1.20.1-14.el9"
    return check


def test_the_kind_list_is_populated_and_mostly_builds_commands():
    """Anti-vacuity for the test below. If `CHECK_KINDS` were empty, or if
    `argv_for` regressed to returning `None` for everything, the coverage
    test would pass while checking nothing at all — the "parametrised list
    came out empty and was skipped in silence" failure CLAUDE.md names."""
    from sentinel.patch import checks as checks_mod
    from sentinel.patch.validator import CHECK_KINDS

    assert len(CHECK_KINDS) >= 10, CHECK_KINDS
    builds = {k for k in CHECK_KINDS
              if checks_mod.argv_for(_sample_check(k), "rhel") is not None}
    assert builds >= {"command", "systemd", "file_exists", "file_absent",
                      "file_sha256", "pkg_version"}, (
        f"a check kind stopped building an argv: {builds}. Either checks.py "
        "changed how it talks to the executor, or argv_for has a hole — and a "
        "hole here makes the coverage test below vacuous.")


@pytest.mark.parametrize("kind", list(_ALL_CHECK_KINDS))
def test_every_built_argv_reaches_the_executors_own_check(kind, monkeypatch):
    """For EVERY check kind: if `checks.py` builds an argv for it, the
    validator must have put that exact argv to the executor's `check_argv`.

    This is the test whose absence let a `systemd` health check on an
    uncontrollable unit, a `file_exists` on /etc/shadow and a `pkg_version`
    on a name containing 'passwd' all validate clean while the executor
    refuses every one of them at run time — a refusal that arrives after the
    apply step has already changed the machine.
    """
    from sentinel.patch import checks as checks_mod
    from sentinel.patch import validator as validator_mod

    sample = _sample_check(kind)
    expected = checks_mod.argv_for(sample, "rhel")

    plan = copy.deepcopy(GOOD_PLAN)
    plan["preflight"].append({
        "id": ("k_" + kind)[:16], "desc_ro": f"verificare {kind}",
        "blocking": False, "check": sample,
    })
    spy = _SpyPolicy()
    monkeypatch.setattr(validator_mod, "_executor_policy", lambda: (spy, None))
    validate_plan(plan, platform_family="rhel")

    if expected is None:
        assert sample.get("argv", []) not in spy.seen or kind == "command"
        return
    assert expected in spy.seen, (
        f"the {kind!r} check builds {expected!r} and sends it to the executor, "
        f"but the validator never asked whether it is permitted. Seen: "
        f"{spy.seen!r}")


def test_a_health_check_on_an_uncontrollable_unit_is_refused():
    """The live case, with the REAL policy rather than a spy: stored plan #1
    on the Ubuntu host is `validated` and health-checks `dbus.service`, which
    `UNCONTROLLABLE_UNITS` forbids. Today that plan applies the package and
    then rolls it back, because the health check cannot be evaluated. It must
    be refused at validation instead — before anyone is asked to approve it."""
    plan = copy.deepcopy(DEBIAN_PLAN)
    plan["health_check"][0]["check"] = {
        "kind": "systemd", "unit": "dbus.service", "expect_state": "active"}

    result = validate_plan(plan, platform_family="debian")

    assert not result.valid
    assert "executor_would_refuse" in {e.code for e in result.errors}
    assert any("dbus.service" in e.message for e in result.errors)


@pytest.mark.parametrize("check,why", [
    ({"kind": "systemd", "unit": "polkit", "expect_state": "active"},
     "a bare unit name the executor refuses"),
    ({"kind": "file_exists", "path": "/etc/shadow"},
     "a protected path"),
    ({"kind": "pkg_version", "name": "passwd-utils", "equals": "1.0"},
     "a forbidden substring in the package name"),
    ({"kind": "file_sha256", "path": "/etc/sentinel/secrets.env",
      "sha256": "0" * 64},
     "a secret path"),
])
def test_refused_check_commands_are_caught_at_validation(check, why):
    """Each of these validated clean before this round, and each is refused by
    the executor at run time. In a preflight that is a wasted approval; in a
    health check it is a rollback of a patch that worked."""
    plan = copy.deepcopy(DEBIAN_PLAN)
    plan["preflight"].append({
        "id": "pf_bad", "desc_ro": f"verificare cu {why}",
        "blocking": True, "check": check,
    })

    result = validate_plan(plan, platform_family="debian")

    assert not result.valid, why
    assert "executor_would_refuse" in {e.code for e in result.errors}, why


def test_both_fixtures_validate_clean_on_their_own_family():
    """The control for every refusal test in this file. Without it, a rule
    that refuses EVERYTHING would leave all of them green — and the operator
    would simply never get a patch plan again, which is a failure that looks
    exactly like safety."""
    for name, plan, family in (("good_plan", GOOD_PLAN, "rhel"),
                               ("debian_plan", DEBIAN_PLAN, "debian")):
        result = validate_plan(copy.deepcopy(plan), platform_family=family)
        assert result.valid, (name, [e.as_dict() for e in result.errors])


def test_a_rollback_pinned_to_a_version_no_preflight_checked_is_refused():
    """The executor can only enforce that `--allow-downgrades` carries a pin;
    it cannot know whether the pinned version is the one the plan verified was
    installed. A rollback to `0.99-1` in a plan whose preflight confirms
    `0.105-1` installs a version this host may never have run — and it runs at
    the moment something has already gone wrong, which is the worst time to
    discover it."""
    plan = copy.deepcopy(DEBIAN_PLAN)
    plan["rollback"][0]["argv"] = ["apt-get", "-y", "install",
                                   "--allow-downgrades", "polkitd=0.99-1"]

    result = validate_plan(plan, platform_family="debian")

    assert not result.valid
    assert "rollback_pin_mismatch" in {e.code for e in result.errors}


def test_a_rollback_that_downgrades_an_unrelated_package_is_refused():
    """`--allow-downgrades openssl=1.0.2` in a plan about polkitd: the
    executor's grammar accepts it (it is pinned), and the operator approved a
    button labelled "roll back the polkitd patch". Nothing but the plan as a
    whole can catch this, so the plan as a whole is where it is caught."""
    plan = copy.deepcopy(DEBIAN_PLAN)
    plan["rollback"][0]["argv"] = ["apt-get", "-y", "install",
                                   "--allow-downgrades", "openssl=1.0.2"]

    result = validate_plan(plan, platform_family="debian")

    assert not result.valid
    assert "rollback_pin_unverified" in {e.code for e in result.errors}


def test_the_dpkg_options_value_is_not_mistaken_for_a_package_pin():
    """`-o Dpkg::Options::=--force-confold` is on the executor's apt
    allowlist, carries no leading dash and does contain an `=` — so the pin
    check read it as a pin of a package called `Dpkg` and refused a plan the
    executor is perfectly happy with. A rule that refuses correct plans is
    not a safer rule; it is the same outage with a different cause."""
    plan = copy.deepcopy(DEBIAN_PLAN)
    plan["rollback"][0]["argv"] = [
        "apt-get", "-y", "-o", "Dpkg::Options::=--force-confold",
        "install", "--allow-downgrades", "polkitd=0.105-1"]

    result = validate_plan(plan, platform_family="debian")

    assert result.valid, [e.as_dict() for e in result.errors]


def test_a_refused_pkg_version_is_caught_even_with_no_platform_family():
    """`platform_family=None` is the standalone skill CLI, which genuinely
    does not know the host. Only `pkg_version`'s argv depends on the family,
    so the plan is examined once per known family rather than skipped — a
    package name the executor refuses is refused on rhel and on debian alike,
    and "I do not know which host" is not a reason to hand back a plan that
    cannot run on either."""
    plan = copy.deepcopy(GOOD_PLAN)
    plan["preflight"][0]["check"] = {
        "kind": "pkg_version", "name": "passwd-utils", "equals": "1.0"}

    result = validate_plan(plan, platform_family=None)

    assert not result.valid
    assert "executor_would_refuse" in {e.code for e in result.errors}


def test_an_unreadable_check_builder_refuses_the_plan(monkeypatch):
    """Same rule as the policy module: if the validator cannot load the code
    that builds the checks' commands, it does not know what those checks will
    run as root. Unknown is refused, with the reason — not waved through."""
    from sentinel.patch import validator as validator_mod

    monkeypatch.setattr(
        validator_mod, "_check_argv_builder",
        lambda: (None, "ModuleNotFoundError: No module named 'sentinel.patch.checks'"))

    result = validate_plan(copy.deepcopy(GOOD_PLAN), platform_family="rhel")

    assert not result.valid
    assert "check_builder_unreadable" in {e.code for e in result.errors}
