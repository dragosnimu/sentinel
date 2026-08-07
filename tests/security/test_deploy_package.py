"""What the deploy tarball is allowed to carry — and what it must not.

This file exists because of a failure that produced no error message. The
exclude list in both deploy scripts predates `watcher/`, so every deployment
silently compressed 400 MB of `node_modules` and appeared to freeze at
"packaging the repository". Nothing was wrong enough to print anything.

Two invariants are checked here, and they are different in kind:

* `watcher/` must never be shipped to the monitored host. That is a design
  property, not an optimisation — the external witness is worth having only
  where the monitored machine cannot reach it.
* the two scripts must not drift. They are advertised as behavioural twins,
  and a divergence in what gets packaged is exactly the kind that goes
  unnoticed until someone deploys from the other operating system.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SH = REPO / "scripts" / "deploy.sh"
PS1 = REPO / "scripts" / "deploy.ps1"

# Directories that must never reach the monitored host, each for its own
# reason. The reason is worth keeping next to the name: a future reader
# deleting one of these should have to argue with the reason, not just the
# entry.
FORBIDDEN = {
    "./secrets": "secrets travel on stdin; a tarball lingers in /tmp",
    "./.git": "history, branches and remotes are not deployment inputs",
    "./watcher": "the external witness must not live on the monitored host",
    "node_modules": "hundreds of megabytes, none of it executed here",
    ".next": "build output of an app that does not run on this machine",
}


def _excludes(text: str) -> set[str]:
    """Every --exclude='...' argument in a script, quoting style ignored."""
    return set(re.findall(r"--exclude=['\"]([^'\"]+)['\"]", text))


@pytest.fixture(scope="module")
def sh_text() -> str:
    return SH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ps1_text() -> str:
    return PS1.read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("name", sorted(FORBIDDEN))
def test_bash_excludes(sh_text: str, name: str) -> None:
    assert name in _excludes(sh_text), f"deploy.sh must exclude {name}: {FORBIDDEN[name]}"


@pytest.mark.parametrize("name", sorted(FORBIDDEN))
def test_powershell_excludes(ps1_text: str, name: str) -> None:
    assert name in _excludes(ps1_text), f"deploy.ps1 must exclude {name}: {FORBIDDEN[name]}"


def test_the_two_scripts_package_the_same_tree(sh_text: str, ps1_text: str) -> None:
    """Twins, or one of them is a trap for whoever uses the other OS."""
    assert _excludes(sh_text) == _excludes(ps1_text)


def test_both_scripts_cap_the_package_size(sh_text: str, ps1_text: str) -> None:
    """A ceiling is what turns the next omission into a message.

    The exclude list will fall behind the repository again — it already has
    once. When it does, the failure should be one line, not a wait long enough
    that the operator reaches for Ctrl+C.
    """
    bash_cap = re.search(r"PACKAGE_MAX_KB=(\d+)", sh_text)
    ps_cap = re.search(r"\$PackageMaxKb\s*=\s*(\d+)", ps1_text)
    assert bash_cap, "deploy.sh has no PACKAGE_MAX_KB"
    assert ps_cap, "deploy.ps1 has no $PackageMaxKb"
    assert bash_cap.group(1) == ps_cap.group(1), "the two ceilings differ"

    # Enforced, not merely defined. A constant nobody compares against is
    # documentation pretending to be a check.
    assert "size_kb > PACKAGE_MAX_KB" in sh_text
    assert "$sizeKb -gt $PackageMaxKb" in ps1_text


@pytest.mark.skipif(shutil.which("tar") is None, reason="no tar on PATH")
def test_the_real_package_stays_under_the_ceiling(sh_text: str) -> None:
    """Build what deploy.sh builds and weigh it.

    The parametrised tests above check the list. This one checks reality: an
    exclude can be present and still not match, which is precisely how
    `watcher/node_modules` slipped through the `.next` era unnoticed.
    """
    cap_kb = int(re.search(r"PACKAGE_MAX_KB=(\d+)", sh_text).group(1))  # type: ignore[union-attr]
    args = [f"--exclude={e}" for e in sorted(_excludes(sh_text))]

    with tempfile.TemporaryDirectory() as tmp:
        tarball = Path(tmp) / "probe.tar.gz"
        subprocess.run(
            ["tar", *args, "-czf", tarball.as_posix(), "-C", REPO.as_posix(), "."],
            check=True, capture_output=True,
        )
        size_kb = tarball.stat().st_size // 1024
        assert size_kb < cap_kb, f"package is {size_kb} KB, ceiling is {cap_kb} KB"

        with tarfile.open(tarball) as tf:
            names = tf.getnames()

    leaked = [n for n in names
              if "/watcher/" in n or "node_modules" in n or "/.next/" in n]
    assert not leaked, f"excluded paths present in the package: {leaked[:5]}"

    # A package that excluded everything would pass every assertion above.
    assert any(n.startswith("./deploy/install.sh") for n in names)
    assert any(n.startswith("./sentinel/") for n in names)
