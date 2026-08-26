"""systemd hardening, and the two units that deliberately do not meet it.

P10's acceptance criterion was `systemd-analyze security` ≤ 3.0 on every unit.
Ten of twelve meet it. The two that do not are both root, and no amount of
directives moves a root service under 3.0 — `User=root` alone is 0.4 and the
whole "runs as root" family dominates the score. Pretending otherwise would
mean either weakening the two components that must not be weakened, or quietly
restating the criterion.

So this file pins what is achievable and names the exceptions.

## Why the lists are read off the disk

They used to be typed here. That list aged the way hand-maintained lists age —
quietly, at the next unit added — and it had already gone wrong before anyone
looked: **`sentinel-beacon` appeared in neither `UNPRIVILEGED` nor
`PRIVILEGED`, so not one hardening assertion in this file had ever been applied
to the beacon unit.** Every test below was green, and one of the fourteen units
was simply not in the room.

That is the same defect as the one this repository keeps producing — a check
that confirms what its author remembered rather than what is there — so the
inventory is now `deploy/systemd/*.service`, and a new unit is covered the
moment it exists. Only `PRIVILEGED` stays written by hand, and deliberately: a
unit that runs as root must be a conscious act, so adding one fails this file
until someone writes the name down next to a reason. `test_the_privilege_split_
matches_the_files` is what keeps the hand-written half honest.

Three places in this repository enumerate units — the installer (a glob, fine),
this file, and `scripts/smoke-test.sh`. The third is asserted from here too,
because a unit that can legitimately be `inactive` and is not exempted there
makes the documented post-deploy check report a failed deployment on every host.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
UNITS = REPO / "deploy" / "systemd"
SMOKE = REPO / "scripts" / "smoke-test.sh"

BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="no bash on PATH")


def _unit(name: str) -> str:
    return (UNITS / f"{name}.service").read_text(encoding="utf-8")


def _directive(unit: str, key: str) -> list[str]:
    """Every value given for a directive, in file order, CR stripped.

    The working tree is CRLF on Windows; a trailing `\\r` on `Restart=always`
    turns every comparison below into a silent mismatch, which is the same
    failure the line-ending guard exists for.
    """
    return [line.split("=", 1)[1].strip()
            for line in unit.splitlines() if line.startswith(key)]


def _one(unit: str, key: str, default: str = "") -> str:
    values = _directive(unit, key)
    return values[-1] if values else default


# The inventory. Everything under deploy/systemd/, no exceptions and no memory.
ALL_UNITS = sorted(p.stem for p in UNITS.glob("*.service"))
assert ALL_UNITS, f"no units found under {UNITS} — the inventory would be empty"

# Root by construction, and documented as such. Hand-written ON PURPOSE: see
# the module docstring. Everything else is unprivileged by derivation.
PRIVILEGED = ["sentinel-executor", "sentinel-watchdog"]
UNPRIVILEGED = [name for name in ALL_UNITS if name not in PRIVILEGED]


def test_the_privilege_split_matches_the_files():
    """The hand-written half of the inventory, checked against the units.

    Without this, `PRIVILEGED` is just a way to opt a unit out of every
    assertion in this file by typing its name — and a new root unit that nobody
    listed would be tested as if it dropped privilege, which is worse than not
    testing it at all.
    """
    for name in ALL_UNITS:
        runs_as = _one(_unit(name), "User=", "root")
        if name in PRIVILEGED:
            assert runs_as == "root", \
                f"{name} is listed as privileged but runs as {runs_as!r} — drop it from the list"
        else:
            assert runs_as == "sentinel", \
                (f"{name} runs as {runs_as!r} and is not in PRIVILEGED. A root unit "
                 f"must be added there with a reason, not tested as if it were not root.")


def test_every_unit_on_disk_is_covered_by_this_file():
    """The assertion that would have caught the beacon.

    `sentinel-beacon` sat in neither list for months while this file reported
    green. A count is not proof of coverage on its own, but combined with the
    derivation above it is: the two lists partition the directory, so a unit
    cannot be present and unasserted.
    """
    assert sorted(UNPRIVILEGED + PRIVILEGED) == ALL_UNITS
    assert "sentinel-beacon" in UNPRIVILEGED, \
        "the unit whose absence this test exists for is missing again"
    assert "sentinel-shipper" in UNPRIVILEGED


@pytest.mark.parametrize("name", UNPRIVILEGED)
def test_unprivileged_units_run_as_sentinel(name):
    assert "User=sentinel" in _unit(name)
    assert "User=root" not in _unit(name)


@pytest.mark.parametrize("name", UNPRIVILEGED)
def test_unprivileged_units_deny_namespaces(name):
    """Creating a user namespace is a standard step in turning a code-execution
    bug into a privilege escalation. None of these has any use for one."""
    unit = _unit(name)
    value = next((l.split("=", 1)[1].strip() for l in unit.splitlines()
                  if l.startswith("RestrictNamespaces=")), None)
    # systemd spells the same thing several ways; all of them deny.
    assert value in ("yes", "true", "1", "on"),         f"{name}: RestrictNamespaces={value!r}"


@pytest.mark.parametrize("name", UNPRIVILEGED)
def test_the_syscall_allow_list_comes_before_the_denials(name):
    """Order decides the mode. Starting with a `~` entry makes the whole list a
    deny-list and a later allow-list entry does not apply — systemd-analyze then
    reports "does not filter system calls" for a unit that looks filtered.

    That shipped in two units and cost 1.6 points each until it was noticed."""
    unit = _unit(name)
    filters = [l.split("=", 1)[1] for l in unit.splitlines()
               if l.startswith("SystemCallFilter=")]
    if not filters:
        pytest.skip(f"{name} defines no syscall filter")
    assert not filters[0].startswith("~"), \
        f"{name}: the first SystemCallFilter is a denial, so nothing is allow-listed"


@pytest.mark.parametrize("name", UNPRIVILEGED + PRIVILEGED)
def test_every_unit_keeps_the_filesystem_read_only_by_default(name):
    """`ProtectSystem=full` looks like hardening and leaves /etc writable.

    The difference is the whole point: `strict` makes the entire filesystem
    read-only except what `ReadWritePaths` names, so a component that is
    supposed to touch nothing can touch nothing. Downgraded to `full`, a
    code-execution bug in any of these can rewrite `/etc/sentinel/sentinel.yaml`
    — turn off auto-block, empty the allowlist, point the beacon somewhere else
    — and the next restart applies it. Nothing in this repository would report
    that; the config is read, not audited.

    It was unasserted until August 2026: changing `strict` to `full` left the
    whole suite green.
    """
    assert _one(_unit(name), "ProtectSystem=") == "strict", \
        f"{name}: ProtectSystem is not strict, so /etc is writable"


@pytest.mark.parametrize("name", UNPRIVILEGED)
def test_no_unprivileged_unit_may_write_the_configuration_it_reads(name):
    """The secrets and the config are inputs. Nothing that runs as `sentinel`
    has any business writing them.

    Both halves are asserted, and the second is the one that bites: dropping
    `ReadOnlyPaths=/etc/sentinel` from a unit leaves `ProtectSystem=strict`
    covering /etc anyway *today*, but the moment that unit gains a
    `ReadWritePaths` entry for an unrelated directory nobody re-derives what
    else became writable. Naming /etc/sentinel read-only says it on purpose.

    The two root units are excluded by construction, not by oversight:
    `sentinel-executor` writes config during a patch rollback and
    `sentinel-watchdog` clears the blocklist — both have /etc/sentinel in
    `ReadWritePaths`, which is exactly what this forbids for everyone else.
    """
    unit = _unit(name)
    read_only = " ".join(_directive(unit, "ReadOnlyPaths=")).split()
    writable = " ".join(_directive(unit, "ReadWritePaths=")).split()
    assert "/etc/sentinel" in read_only, \
        f"{name}: /etc/sentinel is not in ReadOnlyPaths"
    assert "/etc/sentinel" not in writable, \
        f"{name}: /etc/sentinel is writable by an unprivileged unit"


@pytest.mark.parametrize("name", UNPRIVILEGED + PRIVILEGED)
def test_every_unit_restricts_its_address_families(name):
    assert "RestrictAddressFamilies=" in _unit(name)


@pytest.mark.parametrize("name", UNPRIVILEGED + PRIVILEGED)
def test_every_unit_bounds_its_memory(name):
    """A leak in one component must not OOM the application this host exists to
    run — which is what the OOM killer would choose, being the largest process."""
    assert "MemoryMax=" in _unit(name)


# --- the exceptions, stated rather than hidden ------------------------------
def test_the_executor_documents_what_it_gives_up_and_why():
    """It scores 4.8 rather than under 3.0 because it is root and runs the
    package manager. Both facts are load-bearing, and the unit says so."""
    unit = _unit("sentinel-executor")
    assert "NoNewPrivileges=false" in unit
    assert "PrivateDevices=false" in unit
    # Not silent: the file explains the trade rather than leaving a reader to
    # assume it was an oversight.
    assert "scriptlets" in unit or "setuid" in unit
    assert "score" in unit.lower()


def test_the_executor_still_denies_what_it_can():
    """Root is not an excuse for the rest."""
    unit = _unit("sentinel-executor")
    for directive in ("RestrictNamespaces=yes", "RestrictSUIDSGID=true",
                      "SystemCallArchitectures=native", "ProtectControlGroups=true",
                      "MemoryDenyWriteExecute=true", "IPAddressDeny=any"):
        assert directive in unit, f"executor is missing {directive}"


def test_the_watchdog_is_left_minimal_on_purpose():
    """It is the anti-lockout deadman: root, dependency-free, and it must work
    precisely when everything else has failed. Every directive added here is
    another way it could fail to start, which is the one failure that has no
    recovery — so it stays as it is, at 6.1, deliberately."""
    unit = _unit("sentinel-watchdog")
    assert "User=root" in unit
    assert "depends on NOTHING" in unit or "dependency" in unit.lower()
    # It has exactly the one capability it needs to flush the blocklist.
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in unit


# --- the third place that enumerates units ---------------------------------
#
# `scripts/smoke-test.sh` is the documented post-deploy verification
# (docs/DEPLOYMENT.md §468, docs/OPERARE.md §92, docs/TESTARE.md §52). It lists
# units by globbing /etc/systemd/system, and install.sh installs every
# deploy/systemd/*.service, so a unit added here appears there with no further
# work — including in the "is it running?" loop.
def _opt_in_daemons() -> list[str]:
    """Units that may legitimately sit `inactive` on a healthy host.

    Derived, not remembered. A daemon is opt-in exactly when it is a long-lived
    process (`Type=exec`) with no timer to trigger it and `Restart=on-failure`
    rather than `always` — that combination is only ever chosen for a component
    whose `run_forever` returns immediately when the operator has not enabled
    it, leaving the unit inactive with exit 0.

    `Restart=always` is the counter-case and it is why this is not simply "every
    daemon": such a unit CANNOT be legitimately inactive, so exempting one would
    hide a real crash.
    """
    out = []
    for name in ALL_UNITS:
        unit = _unit(name)
        if (UNITS / f"{name}.timer").exists():
            continue
        if _one(unit, "Type=") != "exec":
            continue
        if _one(unit, "Restart=") == "on-failure":
            out.append(f"{name}.service")
    return out


def _smoke_opt_in_block() -> str:
    """The one-liner smoke-test.sh asks the config loader, verbatim."""
    text = SMOKE.read_text(encoding="utf-8")
    match = re.search(r'opt_in_raw="\$\((.*?)\|\| true\)"', text, re.S)
    assert match, "smoke-test.sh no longer builds opt_in_raw the way this test reads it"
    return match.group(1)


def test_every_opt_in_daemon_is_exempted_by_the_smoke_test():
    """The failure this prevents: a correct deployment reported as failed.

    `smoke-test.sh` prints „Verificări eșuate. Nu considera deployment-ul
    reușit." and exits 1 when a unit is `inactive` with no timer and no
    exemption. `sentinel-shipper` shipped in exactly that state: installed by
    the glob, never started because `ship.enabled` is false on every host, and
    absent from an exemption list that had one name hard-coded into it. The
    operator's documented verification would have failed on every host,
    including all the ones where nothing whatsoever was wrong.

    That is the false alarm the exemption's own thirty-line comment exists to
    prevent, reintroduced by the mechanism it describes.
    """
    block = _smoke_opt_in_block()
    daemons = _opt_in_daemons()
    assert daemons, "the derivation found no opt-in daemons; it has stopped working"
    for unit in daemons:
        assert unit in block, (
            f"{unit} can legitimately be inactive but smoke-test.sh does not exempt it — "
            f"every deploy would report a failed deployment. Add it to the config "
            f"one-liner in scripts/smoke-test.sh.")


def test_the_smoke_test_exempts_nothing_that_must_stay_running():
    """The other direction, and the more dangerous one.

    An exemption is a promise that `inactive` is fine. Given to a
    `Restart=always` unit, it converts a dead collector — no ingestion, no
    detection, no alerts — into a green line in the deployment report. The
    smoke test's own comment says this about `sentinel-ai` and nothing enforced
    it.
    """
    block = _smoke_opt_in_block()
    for name in ALL_UNITS:
        if _one(_unit(name), "Restart=") != "always":
            continue
        assert f"{name}.service" not in block, (
            f"{name} has Restart=always and so cannot legitimately be inactive; "
            f"exempting it would hide a crashed daemon behind a green report.")


def test_the_smoke_test_builds_unit_names_it_does_not_assemble():
    """`sentinel-${comp}.service` over a config section named `ship` produces
    `sentinel-ship.service` — a name matching no unit, so the exemption silently
    exempts nothing and the false failure survives the fix meant to remove it.

    The unit name must therefore travel whole from the one-liner. Asserted on
    the shape of the loop, because that is where the assembly used to happen.
    """
    # Comment lines dropped first. The script explains in prose why assembling
    # the name is wrong, and a test that cannot tell an explanation from the
    # mistake it describes is a test that punishes writing the explanation down.
    code = "\n".join(line for line in SMOKE.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    assert "sentinel-${comp}.service" not in code, \
        "smoke-test.sh assembles a unit name from a config section name again"
    assert re.search(r"while read -r unit_name enabled", code), \
        "the opt-in loop no longer reads a whole unit name"


# --- the read itself, run rather than read ---------------------------------
#
# Everything above asserts on the TEXT of smoke-test.sh. That is enough to
# notice a missing exemption and not enough to notice a missing READ: a
# truncated one-liner produces output that looks perfectly well-formed, and the
# text is unchanged. So this last group executes the shipped classification.
def _lift_classifier() -> str:
    """`OPT_IN_DONE` and `read_opt_in_units`, cut verbatim out of the script."""
    text = SMOKE.read_text(encoding="utf-8")
    match = re.search(r"^OPT_IN_DONE=.*?^read_opt_in_units\(\)\s*\{.*?^\}",
                      text, re.S | re.M)
    assert match, "smoke-test.sh no longer defines read_opt_in_units()"
    return match.group(0)


def _classify(raw: str) -> tuple[str, list[str]]:
    script = (
        "set -u\n"
        + _lift_classifier()
        + '\nread_opt_in_units "$RAW"\n'
        'printf "%s\\n" "$OPT_IN_STATUS"\n'
        'printf "%s\\n" "$OPT_IN_OFF"\n'
    )
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          env={**os.environ, "RAW": raw, "NO_COLOR": "1"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    status, _, units = proc.stdout.partition("\n")
    return status.strip(), units.split()


@needs_bash
def test_a_truncated_config_read_is_not_treated_as_a_complete_one():
    """The failure this prevents is silent, and it was measured, not reasoned.

    The one-liner runs on the HOST, with the host's code; this script comes from
    the repository. When the repository is newer — between `git pull` and the
    deploy, or if someone verifies before installing — a config section the host
    does not have raises `AttributeError` mid-statement. And then:

        $ python -c 'print("a"); raise AttributeError'   ->   stdout: "a"

    Python flushes what it already printed, the traceback goes to stderr where
    `$( )` never looks, and `|| true` eats the exit code. So the output is NOT
    empty — it is the lines before the break. The "could not read" branch is
    skipped, no warning is printed, and every opt-in daemon listed AFTER the
    broken line is silently un-exempted: `smoke-test.sh` then reports a failed
    deployment on a healthy host with nothing anywhere saying why.

    Today the ordering hides it — `ship` happens to be last. A third opt-in
    daemon loses that accident, and E3 is where daemons get added.

    Nothing is exempted from a partial read, deliberately: a partial truth about
    which services may be off is not a smaller truth, it is an unknown one.
    """
    status, units = _classify("sentinel-beacon.service False")
    assert status == "parțial", status
    assert units == [], \
        "a partial read exempted a service, so the daemons after the break are invisible"


@needs_bash
def test_a_complete_config_read_still_exempts_what_is_off():
    """The other end. A completeness check that never passes turns every deploy
    into a warning, and a warning on every deploy is one nobody reads — the same
    false alarm in a new place."""
    status, units = _classify(
        "sentinel-beacon.service False\n"
        "sentinel-shipper.service False\n"
        "__citire_completa__")
    assert status == "complet", status
    assert units == ["sentinel-beacon.service", "sentinel-shipper.service"], units

    # And an enabled service is still required to be running.
    status, units = _classify(
        "sentinel-beacon.service True\n"
        "sentinel-shipper.service False\n"
        "__citire_completa__")
    assert status == "complet" and units == ["sentinel-shipper.service"], units


@needs_bash
def test_an_empty_config_read_is_its_own_state():
    """`gol` and `parțial` ask different things of the operator — one says the
    host could not be reached at all, the other names a version skew — so they
    must not collapse into each other."""
    assert _classify("") == ("gol", [])


def test_the_completeness_marker_is_the_last_thing_the_one_liner_prints():
    """A marker that is not last proves nothing.

    Print it before the final `print("sentinel-…", …)` and a read that dies on
    that last statement still carries the marker: the check passes, the daemon
    is un-exempted, and the false failure is back with a completeness check
    standing next to it saying everything was fine.
    """
    block = _smoke_opt_in_block()
    prints = re.findall(r"print\(\\?\"([^\"\\]+)", block)
    assert prints, block
    assert prints[-1] == "__citire_completa__", \
        f"the last thing the one-liner prints is {prints[-1]!r}, not the marker"
    assert prints.count("__citire_completa__") == 1


def test_the_two_halves_of_the_marker_agree():
    """The marker is written twice — in `OPT_IN_DONE` and inside the Python
    one-liner — and nothing but this makes them equal. Divergent, every run
    reports `parțial` forever: loud, permanent, and wrong in the direction that
    exempts nothing, so every deploy on every host would report failure."""
    text = SMOKE.read_text(encoding="utf-8")
    declared = re.search(r'^OPT_IN_DONE="([^"]+)"', text, re.M)
    assert declared, "OPT_IN_DONE is no longer declared"
    assert declared.group(1) in _smoke_opt_in_block(), \
        f"the one-liner does not print {declared.group(1)!r}"


def test_no_unit_grants_a_capability_it_does_not_name():
    """`AmbientCapabilities` without a bounding set is a way to hold more
    privilege than the file appears to grant."""
    for name in UNPRIVILEGED + PRIVILEGED:
        unit = _unit(name)
        if "AmbientCapabilities=" not in unit:
            continue
        ambient = next(l for l in unit.splitlines() if l.startswith("AmbientCapabilities="))
        caps = ambient.split("=", 1)[1].split()
        if not caps:
            continue
        bounding = next((l for l in unit.splitlines()
                         if l.startswith("CapabilityBoundingSet=")), "")
        for cap in caps:
            assert cap in bounding, f"{name}: {cap} is ambient but not in the bounding set"
