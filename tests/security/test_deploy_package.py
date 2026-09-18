"""What the deploy tarball is allowed to carry — and what it must not.

This file exists because of a failure that produced no error message. The
exclude list in both deploy scripts predates `watcher/`, so every deployment
silently compressed 400 MB of `node_modules` and appeared to freeze at
"packaging the repository". Nothing was wrong enough to print anything.

Superseded 8 Sep 2026: `deploy.sh`/`deploy.ps1` no longer build the package
with a hand-maintained `--exclude=` list at all — they call
`build_sentinel_package` / `Build-Package.ps1` (scripts/lib/), which packages
what `git ls-files` returns, minus pathspecs for the categories that ARE
tracked but do not belong on the wire. `.git`, `node_modules` and `.next` need
no pathspec at all: git never tracks them in the first place, so
`git ls-files` never returns them — the reason `--exclude=` for those three no
longer appears anywhere, and grepping for it would be testing for a mechanism
that has been retired, not a gap in the current one.

Two invariants are checked here, and they are different in kind:

* `secrets/` and `watcher/` must never be shipped to the monitored host — the
  first because secrets travel over stdin and a tarball lingers in /tmp, the
  second because the external witness is worth having only where the
  monitored machine cannot reach it. Checked as PATHSPECS, because those are
  tracked categories a pathspec has to name explicitly.
* the two scripts must not drift. They are advertised as behavioural twins,
  and a divergence in what gets packaged is exactly the kind that goes
  unnoticed until someone deploys from the other operating system.
* `.git`, `node_modules`, `.next` — never tracked, so checked on the REAL
  archive instead of in source text: an untracked category needs no pathspec,
  but "needs no pathspec" and "actually never shows up" are a git behaviour,
  not a promise, worth confirming against the real repository once.
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
BUILD_SH = REPO / "scripts" / "lib" / "build-package.sh"
BUILD_PS1 = REPO / "scripts" / "lib" / "Build-Package.ps1"

BASH = shutil.which("bash")
GIT = shutil.which("git")
TAR = shutil.which("tar")
needs_bash = pytest.mark.skipif(BASH is None, reason="no bash on PATH")
needs_git = pytest.mark.skipif(GIT is None, reason="no git on PATH")
needs_tar = pytest.mark.skipif(TAR is None, reason="no tar on PATH")

# Tracked categories that must never reach the monitored host — checked as
# PATHSPECS in the packaging libraries, each for its own reason, worth
# keeping next to the name so a future reader deleting one has to argue with
# the reason, not just the entry.
FORBIDDEN_TRACKED = {
    "secrets": "secrets travel on stdin; a tarball lingers in /tmp",
    "watcher": "the external witness must not live on the monitored host",
}

# Categories git never tracks at all, checked on the REAL built archive —
# see the module docstring for why a pathspec cannot be the thing tested here.
FORBIDDEN_UNTRACKED_MARKERS = ("/watcher/", "node_modules", "/.next/")


def _pathspecs(text: str) -> set[str]:
    """Every `':!something'` pathspec in a packaging library, bash or
    PowerShell — the syntax is identical in both."""
    return set(re.findall(r"':!([^']+)'", text))


def _posix(path: Path) -> str:
    """A path `tar`/`git` under Git Bash accept, on any OS these tests run on."""
    return str(path).replace("\\", "/")


def _tar_dest(path: Path) -> str:
    """Where `tar -f` may WRITE, which is stricter than where git may read.

    GNU tar parses `C:/tmp/x.tar.gz` as `host:path` and tries to resolve a
    machine called `C` — "Cannot connect to C: resolve failed", RC=2. So this
    test failed on Windows for a reason that has nothing to do with the
    package being built, and it failed INVISIBLY until now: the untracked-file
    gate made it skip before it ever reached tar. A drive-letter path becomes
    the /c/... form Git Bash mounts it at.
    """
    text = _posix(path)
    if len(text) > 1 and text[1] == ":":
        return "/" + text[0].lower() + text[2:]
    return text


@pytest.fixture(scope="module")
def sh_pathspecs() -> set[str]:
    return _pathspecs(BUILD_SH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def ps1_pathspecs() -> set[str]:
    return _pathspecs(BUILD_PS1.read_text(encoding="utf-8-sig"))


@pytest.fixture(scope="module")
def sh_text() -> str:
    return SH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ps1_text() -> str:
    return PS1.read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("name", sorted(FORBIDDEN_TRACKED))
def test_bash_pathspecs_exclude_the_forbidden_tracked_categories(sh_pathspecs, name):
    assert name in sh_pathspecs, (
        f"scripts/lib/build-package.sh must exclude {name}: {FORBIDDEN_TRACKED[name]}")


@pytest.mark.parametrize("name", sorted(FORBIDDEN_TRACKED))
def test_powershell_pathspecs_exclude_the_forbidden_tracked_categories(ps1_pathspecs, name):
    assert name in ps1_pathspecs, (
        f"scripts/lib/Build-Package.ps1 must exclude {name}: {FORBIDDEN_TRACKED[name]}")


def test_the_two_scripts_package_the_same_tree(sh_pathspecs, ps1_pathspecs) -> None:
    """Twins, or one of them is a trap for whoever uses the other OS."""
    assert sh_pathspecs == ps1_pathspecs, (
        f"only in build-package.sh: {sh_pathspecs - ps1_pathspecs} · "
        f"only in Build-Package.ps1: {ps1_pathspecs - sh_pathspecs}")


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


def test_neither_deploy_script_builds_the_package_with_an_exclude_list(sh_text: str, ps1_text: str) -> None:
    """Regression, direct: if `--exclude=` reappears at the packaging call
    site in either script, the old mechanism is back — the one that shipped
    `credentiale.txt` and `env.txt` because a denylist cannot be told about a
    name before that name exists.
    """
    assert "--exclude=" not in sh_text, (
        "deploy.sh builds the package with --exclude= — should call build_sentinel_package")
    assert "--exclude=" not in ps1_text, (
        "deploy.ps1 builds the package with --exclude= — should call Build-Package.ps1")


@needs_bash
@needs_tar
@needs_git
def test_the_real_package_stays_under_the_ceiling(sh_text: str) -> None:
    """Build what deploy.sh actually builds — `build_sentinel_package` over
    THIS repository — and weigh it.

    The parametrised tests above check the pathspec list. This one checks
    reality: a pathspec can be present and still not matter if the function
    that reads it is never reached, which is precisely how
    `watcher/node_modules` slipped through the `.next` era unnoticed under the
    old `--exclude=` mechanism.
    """
    cap_kb = int(re.search(r"PACKAGE_MAX_KB=(\d+)", sh_text).group(1))  # type: ignore[union-attr]

    with tempfile.TemporaryDirectory() as tmp:
        tarball = Path(tmp) / "probe.tar.gz"
        script = (
            "set -u\n"   # nu -e: RC=3 (fișiere neurmărite) e un rezultat citit, nu o eroare de script
            f'source "{_posix(BUILD_SH)}"\n'
            f'build_sentinel_package "{_tar_dest(tarball)}" "{_posix(REPO)}"\n'
            'echo "RC=$?"\n'
        )
        proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
        out = proc.stdout + proc.stderr
        if "RC=3" in proc.stdout:
            # Nu un defect al testului sau al mecanismului -- arborele DE LUCRU
            # real, chiar acum, are fișiere netrecute prin `git add` care ar
            # pleca dacă s-ar construi pachetul (vezi predarea agentului: cazul
            # e AȘTEPTAT să refuze pe 8 sep 2026, din cauza
            # sentinel/telegram/callback_sign.py). Plafonul de mărime nu poate
            # fi măsurat cât timp poarta blochează construcția -- „necunoscut",
            # nu „stricat".
            pytest.skip(
                "arborele de lucru are fișiere neurmărite care ar pleca -- "
                f"nu s-a putut construi pachetul ca să se măsoare: {out}")
        assert "RC=0" in proc.stdout, out

        size_kb = tarball.stat().st_size // 1024
        assert size_kb < cap_kb, f"package is {size_kb} KB, ceiling is {cap_kb} KB"

        with tarfile.open(tarball) as tf:
            names = tf.getnames()

    leaked = [n for n in names if any(marker in n for marker in FORBIDDEN_UNTRACKED_MARKERS)]
    assert not leaked, f"excluded paths present in the package: {leaked[:5]}"

    # A package that excluded everything would pass every assertion above.
    #
    # Normalised, because the member names lost their "./" prefix when the
    # packager moved from `tar -C "$REPO_ROOT" .` to `git ls-files | tar -T -`.
    # Both assertions had silently been false ever since — this test skipped
    # before reaching them (untracked files in the tree), so nothing said so,
    # and an anti-vacuity guard that cannot fire is the vacuum it was meant to
    # prevent.
    flat = {n[2:] if n.startswith("./") else n for n in names}
    assert "deploy/install.sh" in flat, sorted(flat)[:10]
    assert any(n.startswith("sentinel/") for n in flat), sorted(flat)[:10]
    # The validator imports `executor.policy` and install.sh step 24 installs
    # it twice from this path; if it stops travelling, every patch plan on the
    # host is refused with `executor_policy_unreadable`.
    assert "executor/policy.py" in flat, (
        "executor/policy.py is not in the package — install.sh reads it from "
        "${SRC_ROOT}/executor/policy.py for both /opt/sentinel/libexec and "
        "/opt/sentinel/lib/executor")
