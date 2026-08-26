"""The line-ending guard: what it must catch, and what it must not invent.

A CR byte in a file that ships to the server fails in a different way for every
consumer, and the worst of them is silent:

* `#!/bin/bash\\r` -> "bad interpreter: /bin/bash^M" — loud, and confusing the
  first time;
* a systemd directive or an nginx value with a trailing CR — the unit or the
  vhost is rejected, loudly enough if anyone reads the output;
* `-k sentinel_ssh\\r` in deploy/audit/sentinel.rules — auditd LOADS the rule.
  The kernel is happy. The key the collector greps for is `sentinel_ssh`, the
  key the events carry is `sentinel_ssh^M`, and the two never meet. The
  intrusion detector goes blind on ssh events and nothing, anywhere, reports a
  fault.

The guard this file covers replaced one that looked for CR under `deploy/` in
`*.sh` and `*.service` and whose comment said it caught "everything else". It
did not catch sentinel.rules, and it did not look at `sentinel/`, `scripts/` or
`executor/` at all — every one of which is inside the tarball, and `executor/`
runs as root.

So these tests EXECUTE the guard against real tarballs. An assertion on the
text of deploy.sh would be the same mistake in a new place: it would confirm
that a line exists, not that the line stops a deploy.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BASH_GUARD = REPO / "scripts" / "lib" / "check-line-endings.sh"
PS_GUARD = REPO / "scripts" / "lib" / "Check-LineEndings.ps1"
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
DEPLOY_PS1 = REPO / "scripts" / "deploy.ps1"

# Real content, so the test breaks when the real file's shape changes rather
# than when a fabricated imitation of it does.
REAL_AUDIT_RULES = (REPO / "deploy" / "audit" / "sentinel.rules").read_bytes()

BASH = shutil.which("bash")
TAR = shutil.which("tar")
POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell")

needs_bash = pytest.mark.skipif(BASH is None, reason="no bash on PATH")
needs_tar = pytest.mark.skipif(TAR is None, reason="no tar on PATH")
needs_powershell = pytest.mark.skipif(POWERSHELL is None, reason="no powershell on PATH")


# ---------------------------------------------------------------------------
# Helpers


def _pack(tmp_path: Path, members: dict[str, bytes], name: str = "pkg.tar.gz") -> Path:
    """Build a tarball shaped like the one deploy.sh builds: `./` prefixed."""
    stage = tmp_path / f"stage-{name}"
    for rel, data in members.items():
        target = stage / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    stage.mkdir(parents=True, exist_ok=True)
    tarball = tmp_path / name
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(stage, arcname=".")
    return tarball


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Decode as UTF-8 and never die on a byte.

    deploy.sh prints a box-drawing banner and Romanian text; the default
    Windows codepage is cp1252 and chokes on both. A test harness that raises
    while reading the output of the thing it is testing reports the wrong
    failure.
    """
    return subprocess.run(
        argv, capture_output=True, text=True,
        encoding="utf-8", errors="replace", **kwargs,
    )


def _run_bash_guard(tarball: Path) -> subprocess.CompletedProcess:
    return _run([BASH, str(BASH_GUARD), _posix(tarball)],
                env={**os.environ, "NO_COLOR": "1"})


def _run_ps_guard(tarball: Path) -> subprocess.CompletedProcess:
    return _run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(PS_GUARD), "-Package", str(tarball)])


def _posix(path: Path) -> str:
    """A path bash's tar will accept.

    Git Bash's tar reads `C:\\Users\\...` as a remote host and dies with
    "Cannot connect to C: resolve failed" — which the guard would report as
    exit 2, an honest answer to the wrong question. cygpath is how the deploy
    scripts' own shell sees the same file.
    """
    if os.name != "nt":
        return str(path)
    cygpath = shutil.which("cygpath")
    if cygpath is None:
        return path.as_posix()
    out = subprocess.run([cygpath, "-u", str(path)], capture_output=True, text=True)
    return out.stdout.strip() or path.as_posix()


def _offenders(proc: subprocess.CompletedProcess) -> set[str]:
    """The file list the guard printed, whichever stream it used.

    Read as the block that follows the header and ends at the first blank
    line. Matching every four-space-indented line instead would also collect
    the `sed -i ...` hint further down and quietly inflate the set — a test
    harness has the same duty to check what it means as the code does.
    """
    text = (proc.stdout or "") + (proc.stderr or "")
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"CR line endings in \d+ file\(s\)", line):
            found = set()
            for candidate in lines[i + 1:]:
                if not candidate.strip():
                    break
                found.add(candidate.strip())
            return found
    return set()


# ---------------------------------------------------------------------------
# What the guard must catch


@needs_bash
@needs_tar
def test_a_cr_in_the_audit_rules_stops_the_deploy(tmp_path: Path) -> None:
    """The blind-collector case: auditd keys with a trailing CR match nothing.

    This is the file the old guard missed, and the failure it produces has no
    error message anywhere — the rules load, the collector runs, and the
    operator sees an ssh detector that simply never fires again.
    """
    pkg = _pack(tmp_path, {
        "deploy/audit/sentinel.rules": REAL_AUDIT_RULES.replace(b"\n", b"\r\n"),
        "deploy/install.sh": b"#!/usr/bin/env bash\nexit 0\n",
    })
    proc = _run_bash_guard(pkg)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "deploy/audit/sentinel.rules" in _offenders(proc)


@needs_bash
@needs_tar
@pytest.mark.parametrize("member", [
    "executor/policy.py",
    "sentinel/collectors/auditd.py",
    "scripts/smoke-test.sh",
    ".claude/skills/sentinel-soc/scripts/sentinel_query.py",
])
def test_a_cr_outside_deploy_stops_the_deploy(tmp_path: Path, member: str) -> None:
    """The second blind spot: the tarball is the whole repo, not just deploy/.

    `tar -C "$REPO_ROOT" .` minus an exclude list ships sentinel/, scripts/,
    executor/ and .claude/. A CR does not break a Python import, but it breaks
    the shebang of anything executed directly — and executor/ runs as root.
    """
    pkg = _pack(tmp_path, {
        member: b"#!/usr/bin/env python3\r\nprint('x')\r\n",
        "deploy/install.sh": b"#!/usr/bin/env bash\nexit 0\n",
    })
    proc = _run_bash_guard(pkg)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert member in _offenders(proc)


@needs_bash
@needs_tar
def test_a_lone_cr_is_caught_too(tmp_path: Path) -> None:
    """CR without LF is not CRLF, and it breaks a shebang just as thoroughly.

    A guard that looks for the two-byte sequence would pass this file. The
    criterion is the CR byte.
    """
    pkg = _pack(tmp_path, {
        "deploy/install.sh": b"#!/usr/bin/env bash\rexit 0\n",
    })
    proc = _run_bash_guard(pkg)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "deploy/install.sh" in _offenders(proc)


# ---------------------------------------------------------------------------
# What the guard must NOT invent


@needs_bash
@needs_tar
def test_a_clean_package_is_accepted(tmp_path: Path) -> None:
    """A guard that refuses everything is not a guard, it is an outage.

    Deploying is how the operator fixes the host. A false alarm here at three
    in the morning costs more than the bug it was meant to prevent.
    """
    pkg = _pack(tmp_path, {
        "deploy/audit/sentinel.rules": REAL_AUDIT_RULES,
        "deploy/install.sh": b"#!/usr/bin/env bash\nexit 0\n",
        "deploy/systemd/sentinel.service": b"[Unit]\nDescription=x\n",
        "sentinel/detect/engine.py": b"X = 1\n",
        "VERSION": b"1.2.3\n",
    })
    proc = _run_bash_guard(pkg)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not _offenders(proc)


@needs_bash
@needs_tar
def test_a_binary_member_is_not_a_false_alarm(tmp_path: Path) -> None:
    """A GeoIP database is full of 0x0D bytes and none of them are line endings.

    Flagging it would train the operator to pass --force past the one check
    that catches the silent auditd failure.
    """
    pkg = _pack(tmp_path, {
        "deploy/geoip/GeoLite2-Country.mmdb": bytes(range(256)) * 40,
        "deploy/install.sh": b"#!/usr/bin/env bash\nexit 0\n",
    })
    proc = _run_bash_guard(pkg)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@needs_bash
@needs_tar
def test_powershell_files_keep_their_crlf(tmp_path: Path) -> None:
    """deploy.ps1 ships because scripts/ ships, and it is CRLF on purpose.

    .gitattributes pins *.ps1 to CRLF. If the guard refused it, no deploy from
    a clean checkout would ever start.
    """
    pkg = _pack(tmp_path, {
        "scripts/deploy.ps1": b"param()\r\nWrite-Host 'x'\r\n",
        "deploy/install.sh": b"#!/usr/bin/env bash\nexit 0\n",
    })
    proc = _run_bash_guard(pkg)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# "Unknown" is not "clean"


@needs_bash
def test_a_missing_package_is_unknown_not_clean(tmp_path: Path) -> None:
    """Reporting 0 for a package it never opened is how a check lies forever.

    Exit 2 exists so the caller can tell "I looked and it is dirty" from "I
    could not look". Both stop a deploy; only one means the tree needs fixing.
    """
    proc = _run_bash_guard(tmp_path / "does-not-exist.tar.gz")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "could not run" in (proc.stdout + proc.stderr)


@needs_bash
def test_a_corrupt_package_is_unknown_not_clean(tmp_path: Path) -> None:
    """A truncated tarball extracts to nothing, and nothing contains no CR."""
    broken = tmp_path / "broken.tar.gz"
    broken.write_bytes(b"\x1f\x8b" + b"garbage" * 20)
    proc = _run_bash_guard(broken)
    assert proc.returncode == 2, proc.stdout + proc.stderr


@needs_bash
@needs_tar
def test_an_empty_package_is_unknown_not_clean(tmp_path: Path) -> None:
    """An empty package passes "no CR found" perfectly, and ships nothing.

    This is the shape of the bug the repository keeps producing: a check that
    succeeds because it had no input, and says so in the language of success.
    """
    pkg = _pack(tmp_path, {}, name="empty.tar.gz")
    proc = _run_bash_guard(pkg)
    assert proc.returncode == 2, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# The two guards must not drift


@needs_bash
@needs_tar
@needs_powershell
def test_the_two_guards_report_the_same_files(tmp_path: Path) -> None:
    """deploy.sh and deploy.ps1 are advertised as behavioural twins.

    An operator who deploys from PowerShell must be stopped by the same files
    that stop an operator deploying from Git Bash. Compared by running both,
    not by comparing their source.
    """
    pkg = _pack(tmp_path, {
        "deploy/audit/sentinel.rules": REAL_AUDIT_RULES.replace(b"\n", b"\r\n"),
        "deploy/install.sh": b"#!/usr/bin/env bash\nexit 0\n",
        "executor/policy.py": b"X = 1\r\n",
        "sentinel/detect/engine.py": b"X = 1\n",
        "scripts/deploy.ps1": b"param()\r\n",
        "deploy/geoip/GeoLite2-Country.mmdb": bytes(range(256)) * 40,
    })
    bash_proc = _run_bash_guard(pkg)
    ps_proc = _run_ps_guard(pkg)

    assert bash_proc.returncode == 1, bash_proc.stdout + bash_proc.stderr
    assert ps_proc.returncode == 1, ps_proc.stdout + ps_proc.stderr
    assert _offenders(bash_proc) == _offenders(ps_proc)
    assert _offenders(bash_proc) == {"deploy/audit/sentinel.rules", "executor/policy.py"}


@needs_bash
@needs_tar
@needs_powershell
def test_the_two_guards_agree_a_clean_package_is_clean(tmp_path: Path) -> None:
    """Twins on the accept path too: one refusing what the other allows is a
    trap for whoever happens to be on the other operating system."""
    pkg = _pack(tmp_path, {
        "deploy/audit/sentinel.rules": REAL_AUDIT_RULES,
        "deploy/install.sh": b"#!/usr/bin/env bash\nexit 0\n",
        "scripts/deploy.ps1": b"param()\r\n",
    })
    assert _run_bash_guard(pkg).returncode == 0
    assert _run_ps_guard(pkg).returncode == 0


# ---------------------------------------------------------------------------
# The wiring: deploy.sh must actually stop


def _repo_copy(tmp_path: Path) -> Path:
    """A copy of the repository deploy.sh can be run against harmlessly.

    secrets/ is NOT copied — the real secrets file must not be duplicated into
    a temporary directory — so a dummy one is written in its place.
    """
    dest = tmp_path / "repo"
    shutil.copytree(
        REPO, dest,
        ignore=shutil.ignore_patterns(
            ".git", "secrets", "watcher", "tests", "docs", "dist",
            "node_modules", ".next", "__pycache__", "*.pyc",
            ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        ),
    )
    (dest / "secrets").mkdir()
    (dest / "secrets" / ".env.local").write_bytes(
        b"SENTINEL_DB_PASSWORD=x\nANTHROPIC_API_KEY=x\n"
        b"TELEGRAM_BOT_TOKEN=x\nTELEGRAM_CHAT_ID=x\n"
    )
    return dest


def _stub_bin(tmp_path: Path) -> Path:
    """ssh and scp that succeed and do nothing.

    The point is to let deploy.sh run its own packaging and its own guard
    without a server. Everything the guard depends on — tar, grep, the
    tarball — is real.
    """
    bin_dir = tmp_path / "stubbin"
    bin_dir.mkdir()
    for name in ("ssh", "scp"):
        stub = bin_dir / name
        stub.write_bytes(b"#!/usr/bin/env bash\nexit 0\n")
        stub.chmod(0o755)
    return bin_dir


def _run_deploy_sh(repo: Path, bin_dir: Path) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "PATH": f"{_posix(bin_dir)}:{os.environ.get('PATH', '')}",
        # tar here is Git Bash's, which cannot write to a "C:\..." TMPDIR.
        "TMPDIR": "/tmp",
        "NO_COLOR": "1",
    }
    return _run(
        [BASH, "./scripts/deploy.sh", "--host", "host.invalid", "--user", "deployer", "--yes"],
        cwd=repo, env=env, timeout=300,
    )


@needs_bash
@needs_tar
@pytest.mark.skipif(os.name != "nt" and shutil.which("cygpath") is None and os.name == "nt",
                    reason="needs a POSIX-ish shell environment")
def test_deploy_sh_stops_when_a_shipped_file_has_a_cr(tmp_path: Path) -> None:
    """The guard has to be WIRED, not merely present.

    Every previous version of this bug class was a check that existed and did
    not stop anything: an exit code nobody read, a stream sent to /dev/null.
    So deploy.sh is run for real — with stub ssh/scp and a throwaway copy of
    the repository — and the assertion is that it does not reach the transfer.
    """
    repo = _repo_copy(tmp_path)
    rules = repo / "deploy" / "audit" / "sentinel.rules"
    rules.write_bytes(rules.read_bytes().replace(b"\n", b"\r\n"))

    proc = _run_deploy_sh(repo, _stub_bin(tmp_path))
    out = proc.stdout + proc.stderr

    assert proc.returncode != 0, out
    assert "deploy/audit/sentinel.rules" in out.replace("\\", "/"), out
    # It must stop BEFORE the package leaves the machine.
    assert "transferring to" not in out, out
    assert "Sentinel deployed to" not in out, out


@needs_bash
@needs_tar
def test_deploy_sh_runs_through_when_nothing_carries_a_cr(tmp_path: Path) -> None:
    """The negative control for the test above.

    Without it, a deploy.sh that died for any other reason — a typo in the
    guard's path, a missing script — would satisfy the failure assertion and
    look like proof.
    """
    repo = _repo_copy(tmp_path)
    _normalise_tree(repo)

    proc = _run_deploy_sh(repo, _stub_bin(tmp_path))
    out = proc.stdout + proc.stderr

    assert proc.returncode == 0, out
    assert "no CR in any text file" in out, out
    assert "Sentinel deployed to" in out, out


def _normalise_tree(root: Path) -> None:
    """Strip CR from every text file under `root`, *.ps1 excepted.

    The working tree this test runs from may itself be carrying CRLF — that is
    the situation the guard exists for — and this test is about deploy.sh's
    accept path, not about the state of the checkout. The check on the real
    tree is test_the_working_tree_ships_no_crlf below.
    """
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() == ".ps1":
            continue
        data = path.read_bytes()
        if b"\x00" in data or b"\r" not in data:
            continue
        path.write_bytes(data.replace(b"\r", b""))


# ---------------------------------------------------------------------------
# The working tree itself


@needs_bash
@needs_tar
def test_the_working_tree_ships_no_crlf() -> None:
    """Fail here, in 0.7 s, rather than at the deploy that follows.

    .gitattributes normalises on commit and on checkout, so it cannot see a
    file rewritten in between — and git actively hides that case: the blob
    still matches HEAD, `git diff` is empty, `git status` shows at most a
    warning in passing. That is how twelve files, one of them
    deploy/audit/sentinel.rules, came to sit in this tree carrying CRLF while
    every git command reported them unchanged.

    If this fails, run the sed the guard prints. If git then says the files are
    unmodified, some tool in the pipeline is rewriting them.

    The set checked is what `tar` puts in the package, derived from deploy.sh's
    own --exclude arguments — deliberately not "every tracked file". tar does
    not read .gitignore, so a file git never sees can still be shipped: that is
    how credentiale.txt, at the repository root, turned out to be inside every
    package. Filtering by git-tracked status would have hidden it, and an
    exemption by name would have hidden it permanently.
    """
    excludes = sorted(set(re.findall(
        r"--exclude=['\"]([^'\"]+)['\"]", DEPLOY_SH.read_text(encoding="utf-8"))))
    assert excludes, "deploy.sh has no --exclude arguments; the package shape is unknown"

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tarball = Path(tmp) / "worktree.tar.gz"
        built = _run(
            [TAR, *[f"--exclude={e}" for e in excludes],
             "-czf", _posix(tarball), "-C", _posix(REPO), "."],
        )
        assert built.returncode == 0, built.stderr
        proc = _run_bash_guard(tarball)

    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# The trees that leave by a different road


# Applications in this repository that run on Linux somewhere OTHER than the
# monitored host, and therefore never appear in the deploy tarball.
EXTERNAL_TREES = ("watcher", "aggregator")

# Suffixes whose bytes are not ours to normalise.
_BINARY = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".mmdb", ".woff",
           ".woff2", ".zip", ".gz", ".whl", ".ttf", ".ps1"}


@pytest.mark.skipif(shutil.which("git") is None,
                    reason="fără git nu se poate afla ce ar pleca din arborii externi, "
                           "deci verificarea NU s-a făcut")
def test_the_externally_deployed_trees_ship_no_crlf() -> None:
    """`watcher/` și `aggregator/` rulează pe Linux, dar nu prin tarball.

    Testul de deasupra derivă mulțimea verificată din `--exclude`-urile lui
    `deploy.sh`, adică răspunde la întrebarea „ce e în PACHET?". E întrebarea
    corectă pentru el, și e scris acolo de ce. Dar din clipa în care un director
    e exclus din pachet, iese și din verificare — iar `aggregator/` tocmai a
    fost exclus. Directoarele astea nu încetează să ruleze pe Linux fiindcă au
    încetat să fie împachetate; doar pleacă pe alt drum (publicare din checkout
    pe găzduire).

    Găsit exact așa: trei fișiere din `aggregator/` au ajuns cu CRLF pe disc
    (un script de întreținere care le-a rescris cu translatarea implicită de
    linii din Python pe Windows), iar nimic nu s-a plâns. Inofensiv pentru
    Node — dar o gardă care încetează să se uite la un director în momentul în
    care acel director încetează să fie livrat pe drumul vechi e o gardă cu o
    gaură, iar gaura crește odată cu directorul.

    Enumerarea e prin `git`, spre deosebire de cea de sus, și diferența e
    intenționată: arborii ăștia se publică DINTR-UN CHECKOUT, deci ce pleacă e
    exact ce vede git — urmărit sau neurmărit-și-neignorat. Un artefact generat
    și ignorat (`next-env.d.ts`, scris de Next cu CRLF) nu pleacă și nu se
    verifică; un fișier nou, neurmărit, pleacă la primul `git add` și se verifică
    de pe acum.
    """
    offenders: list[str] = []
    for args in (["ls-files", "-z", "--"], ["ls-files", "-z", "--others",
                                            "--exclude-standard", "--"]):
        out = subprocess.run(["git", *args, *EXTERNAL_TREES], cwd=REPO,
                             capture_output=True, encoding="utf-8",
                             errors="replace", check=True)
        for rel in (p for p in (out.stdout or "").split("\0") if p):
            path = REPO / rel
            if not path.is_file() or Path(rel).suffix.lower() in _BINARY:
                continue
            data = path.read_bytes()
            # Un NUL înseamnă binar; `\r` acolo nu e un sfârșit de linie.
            if b"\x00" in data or b"\r" not in data:
                continue
            offenders.append(rel)

    assert not offenders, (
        "CR în arbori care rulează pe Linux:\n  " + "\n  ".join(sorted(offenders))
        + "\n  Repară cu:  python -c \"import pathlib,sys;"
          "[p.write_bytes(p.read_bytes().replace(b'\\r\\n',b'\\n')) "
          "for p in map(pathlib.Path, sys.argv[1:])]\" <fișiere>")


# ---------------------------------------------------------------------------
# deploy.ps1's wiring, as far as it can be checked from here


@needs_powershell
def test_deploy_ps1_calls_a_guard_that_exists_and_parses() -> None:
    """The PowerShell twin's call site, checked as far as is possible here.

    This is a weaker test than the ones above and deliberately so: running
    deploy.ps1 end to end needs a Windows OpenSSH stub on PATH and a console,
    which this suite does not have. What it does establish is that the path
    deploy.ps1 names resolves to a real file and that the file parses under
    Windows PowerShell — the two ways a call site rots silently. The guard's
    BEHAVIOUR is covered by the tests that execute it directly.
    """
    text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    call = re.search(r"Join-Path \$PSScriptRoot '([^']+Check-LineEndings\.ps1)'", text)
    assert call, "deploy.ps1 does not invoke Check-LineEndings.ps1"

    named = (DEPLOY_SH.parent / call.group(1).replace("\\", "/")).resolve()
    assert named.is_file(), f"deploy.ps1 points at {named}, which does not exist"

    parsed = _run(
        [POWERSHELL, "-NoProfile", "-Command",
         "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("
         f"'{named}', [ref]$null, [ref]$e); if ($e) {{ $e | ForEach-Object {{ $_.Message }}; exit 1 }}"],
    )
    assert parsed.returncode == 0, parsed.stdout + parsed.stderr

    # The exit code has to be read. A call whose result is ignored is the bug
    # this whole file exists for.
    assert "$LASTEXITCODE -ne 0" in text.split("Check-LineEndings.ps1")[1][:200]
