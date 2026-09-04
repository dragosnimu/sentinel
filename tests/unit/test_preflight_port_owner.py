"""Whose process is holding the port — asked of the kernel, not of a name.

Preflight blocked an upgrade because port 8787 was in use. It was in use by
Sentinel's own dashboard: the deployment could not proceed because the thing
being deployed was running. The message told the operator to stop Sentinel in
order to deploy Sentinel.

The process name cannot settle this. `ss` reports the dashboard as "python",
and so is every other Python service on that host. The cgroup path can: the
kernel writes it, and it carries the systemd unit the process was started
under.

These tests pin the extraction against the shapes /proc/PID/cgroup actually
takes — including the two that must yield nothing, because a false positive
here would wave through a genuine port conflict.
"""

from __future__ import annotations


import shutil
import subprocess
from pathlib import Path

import pytest

COMMON_SH = Path(__file__).resolve().parents[2] / "deploy" / "lib" / "common.sh"

CASES = [
    ("cgroup v2, plain unit",
     "0::/system.slice/sentinel-web.service", "sentinel-web.service"),
    ("cgroup v2, service with sub-cgroups",
     "0::/system.slice/sentinel-web.service/app", "sentinel-web.service"),
    ("cgroup v1, still seen on older hosts",
     "1:name=systemd:/system.slice/sentinel-web.service", "sentinel-web.service"),
    ("templated unit",
     "0::/system.slice/system-getty.slice/getty@tty1.service", "getty@tty1.service"),
    ("someone else's database",
     "0::/system.slice/postgresql.service", "postgresql.service"),
    # The negatives matter more than the positives. Something in a container or
    # a login session holding Sentinel's port IS a conflict, and must stay one.
    ("a docker container is not a unit", "0::/docker/9f2c1ab", ""),
    # Measured on the Ubuntu install target: the process holding 5432 is named
    # "postgres" (a `postgres:16-alpine` image run with `--network host`), but
    # under the systemd cgroup driver Docker places it in a `.scope`, not a
    # `.service` — the PostgreSQL ownership check in
    # tests/security/test_installer_postgres_port.py is keyed on THIS output,
    # not on the process name, exactly so this case comes out empty rather
    # than "ours".
    ("a docker container under the systemd cgroup driver is not a unit either",
     "0::/system.slice/docker-4f2a9c1e8b3d6a7e5f0c9b8a7d6e5f4c.scope", ""),
    ("a login session is not a unit",
     "0::/user.slice/user-1000.slice/session-3.scope", ""),
]


@pytest.mark.skipif(shutil.which("bash") is None, reason="no bash on PATH")
@pytest.mark.parametrize("label,cgroup,expected", CASES, ids=[c[0] for c in CASES])
def test_unit_extracted_from_cgroup(label: str, cgroup: str, expected: str) -> None:
    """Runs the shipped function, not a copy of it.

    An earlier version of this test re-extracted the regex from the file and
    ran it separately. That tests a transcription. Sourcing common.sh and
    calling cgroup_unit tests what the server will actually run.
    """
    # Sourced by relative name from its own directory. An absolute Windows path
    # reaches MSYS bash as `C:/...`, which it reads as a relative path under a
    # directory called `C:` and cannot find. Relative sidesteps the translation
    # entirely and behaves the same on Linux.
    result = subprocess.run(
        ["bash", "-c", "source ./common.sh; cgroup_unit"],
        cwd=COMMON_SH.parent,
        input=cgroup + "\n", capture_output=True, text=True, check=True,
    )
    assert result.stdout.splitlines()[:1] == ([expected] if expected else [])


def test_preflight_only_forgives_sentinel_units() -> None:
    """A port held by anything else must still block.

    The exemption is narrow on purpose. `sentinel-*` is matched as a prefix on
    the unit name — a filename the kernel supplies — rather than on the process
    name, which any process can choose for itself.
    """
    preflight = (COMMON_SH.parent.parent / "preflight.sh").read_text(encoding="utf-8")
    assert 'unit" == sentinel-*' in preflight
    # And the blocking branch still exists for everyone else.
    assert "Sentinel needs it" in preflight
