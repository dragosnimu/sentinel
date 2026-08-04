"""systemd hardening, and the two units that deliberately do not meet it.

P10's acceptance criterion was `systemd-analyze security` ≤ 3.0 on every unit.
Ten of twelve meet it. The two that do not are both root, and no amount of
directives moves a root service under 3.0 — `User=root` alone is 0.4 and the
whole "runs as root" family dominates the score. Pretending otherwise would
mean either weakening the two components that must not be weakened, or quietly
restating the criterion.

So this file pins what is achievable and names the exceptions.
"""
from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
UNITS = REPO / "deploy" / "systemd"

# Everything that is not root. These have no excuse.
UNPRIVILEGED = [
    "sentinel-web", "sentinel-detect", "sentinel-telegram", "sentinel-ingest",
    "sentinel-ai", "sentinel-scan", "sentinel-health", "sentinel-maintenance",
    "sentinel-selfcheck", "sentinel-reconcile",
]

# Root by construction, and documented as such.
PRIVILEGED = ["sentinel-executor", "sentinel-watchdog"]


def _unit(name: str) -> str:
    return (UNITS / f"{name}.service").read_text(encoding="utf-8")


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
