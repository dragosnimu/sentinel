"""Step 21 must not say "installed" about a binary that is not on the host.

Step 21 is the one that puts trivy and nuclei on the server. What shipped was:

    tar -xzf "$tmp" -C /usr/local/bin "$name" 2>/dev/null \\
        || tar -xzf "$tmp" -C /usr/local/bin
    chmod 0755 "/usr/local/bin/${name}" 2>/dev/null || true
    rm -f "$tmp"
    ok "${name} installed"

Both tar invocations can fail — the first is silenced, the second only runs if
the first failed, and it fails too on anything that is not a gzip tarball. The
chmod that would have noticed is neutralised by `|| true`, `rm` succeeds because
`rm -f` always does, and `ok "${name} installed"` is then printed
unconditionally. Nothing anywhere in the step ever looked at /usr/local/bin.

That is the pattern CLAUDE.md is written about, sitting in the step that
installs the security tooling: the exit status of an intention, reported as an
effect. The cost is not an install that fails — it is an install that succeeds
on paper. The operator reads "[+] nuclei installed", the dashboard shows
vulnerabilities from `dnf updateinfo` only, and nothing anywhere says a scanner
is missing. That is a monitoring tool lying, which is worse than one that is
down.

And nuclei could never have worked in any case: for Linux, projectdiscovery
publishes .zip only (linux_386, linux_amd64, linux_arm, linux_arm64). There is
no tar.gz. Both tar attempts would have failed on every host, forever, and the
step would have said "installed" every time.

These tests run the SHIPPED step 21, extracted verbatim between the `# --- 21`
and `# --- 22` markers, against fixture archives and a fake `curl`. `sha256sum`,
`tar`, `unzip`, `od`, `find` and `install` are the real ones. What is asserted
is what the operator sees and what is on disk afterwards — never what the script
appears to say.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path, PurePosixPath

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "deploy" / "install.sh"
MANIFEST = REPO / "deploy" / "tools" / "manifest.txt"
BASH = shutil.which("bash")

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="no bash on PATH")]


def step21_source() -> str:
    """Step 21 as shipped, not a copy of it.

    Taken between the section markers so the timeout constant and the helper
    functions travel with the step. If the markers move, or the block stops
    defining what it is supposed to define, this raises rather than silently
    testing an empty string — a mistake this repository has paid for before.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(r"^# --- 21 -+\n(.*?)^# --- 22 -+$", text, re.S | re.M)
    assert match, "cannot find the step 21 block in install.sh"
    body = match.group(1)
    for needed in ("step_external_tools()", "tool_version_line()",
                   "tool_archive_kind()", "tool_extract()",
                   "tool_report_existing()", "TOOL_PROBE_TIMEOUT_S",
                   "TOOLS_BIN_DIR"):
        assert needed in body, f"step 21 no longer contains {needed}"
    return body


# ---------------------------------------------------------------------------
# Fixtures: archives shaped like the real releases
# ---------------------------------------------------------------------------
# A stand-in binary is a shell script, not a blob, so it can actually be run by
# the step's version probe on the machine the suite runs on.
#
# Measured on Windows/MSYS, 26 Aug 2026: the POSIX mode is NOT observable here.
# `install -m 0644` of a file with a shebang produces `stat -c %a` = 755, bash's
# `-x` is true, and os.access(X_OK) is true for every existing file. Measured on
# AlmaLinux the same day, the same command gives 644, `[ -x ]` false and
# os.access(X_OK) false — so the effect is unobservable on the machine the suite
# usually runs on, not unobservable in general.
#
# Both halves are therefore kept. `test_the_installed_binary_carries_the_mode_it
# _was_given` asserts the real mode behind a runtime probe (write 0644, read it
# back, skip if it did not stick) so a Linux run has teeth;
# `test_the_binary_is_installed_executable` asserts the shipped text, so a
# Windows run still catches a 0755 mutated to 0644. Neither one alone is enough:
# an os.access(X_OK) with no probe in front of it passes here whatever the step
# does, which is the test-that-checks-nothing this repository keeps paying for.
TRIVY_BIN = """#!/usr/bin/env bash
# Answers like cobra does: --version, on stdout.
[[ "$1" == "--version" ]] && { printf 'Version: %s\\n' "${FAKE_TRIVY_VERSION:-0.74.0}"; exit 0; }
exit 1
"""

NUCLEI_BIN = """#!/usr/bin/env bash
# Answers like goflags does: -version, and the banner goes to STDERR. A probe
# that captured stdout only would see nothing and call a good install unproven.
[[ "$1" == "-version" ]] && {
    printf '\\n  __  _  _  ___| |__ ___(_)\\n projectdiscovery.io\\n\\n' >&2
    printf '[INF] Current nuclei version: v%s\\n' "${FAKE_NUCLEI_VERSION:-3.11.1}" >&2
    exit 0
}
exit 1
"""

TRIVY_ASSET = "trivy_0.74.0_Linux-64bit.tar.gz"
NUCLEI_ASSET = "nuclei_3.11.1_linux_amd64.zip"
TRIVY_URL = ("https://github.com/aquasecurity/trivy/releases/download/"
             f"v0.74.0/{TRIVY_ASSET}")
NUCLEI_URL = ("https://github.com/projectdiscovery/nuclei/releases/download/"
              f"v3.11.1/{NUCLEI_ASSET}")


def _targz(members: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in members.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip(members: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in members.items():
            # Deliberately no external_attr: python's zipfile drops the
            # executable bit, which is what the real nuclei zip loses too when
            # unpacked this way. The step must set the mode itself.
            zf.writestr(name, content)
    return buf.getvalue()


TRIVY_TGZ = _targz({"trivy": TRIVY_BIN, "LICENSE": "Apache 2.0\n",
                    "README.md": "# trivy\n"})
NUCLEI_ZIP = _zip({"nuclei": NUCLEI_BIN, "README.md": "# nuclei\n",
                   "LICENSE.md": "MIT\n"})
# A well-formed gzip tarball that simply does not contain the binary. This is
# the shape of the defect: the unpack succeeds and there is nothing to install.
TRIVY_TGZ_NO_BINARY = _targz({"README.md": "# trivy\n", "LICENSE": "Apache\n"})
# Neither gzip nor zip: an HTML error page saved under the asset's name.
NOT_AN_ARCHIVE = b"<html><body>404 Not Found</body></html>\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


FAKE_CURL = """#!/usr/bin/env bash
# Serves $FIXTURE_DIR/<basename of url> into the -o path. A fixture that is not
# there is a 404, which is exactly how a bad manifest URL behaves.
out=""; prev=""
for a in "$@"; do [[ "$prev" == "-o" ]] && out="$a"; prev="$a"; done
url="${@: -1}"
src="${FIXTURE_DIR}/$(basename "$url")"
[[ -f "$src" ]] || exit 22
cp "$src" "$out"
"""

# A shim in front of the real install(1). It records the SOURCE path of every
# `install -D -m 0755 <src> <dst>` the step performs — which is the only way to
# learn, from outside, where the step staged the archive — and then execs the
# real binary so the step behaves exactly as shipped. `echo`, not `printf ...`,
# to keep a backslash out of a string that travels through several layers.
FAKE_INSTALL = """#!/usr/bin/env bash
echo "${@: -2:1}" >> "$INSTALL_SRC_LOG"
exec "$REAL_INSTALL" "$@"
"""

# A binary that answers nothing and hangs on every flag, recording which flag it
# was asked with. `exec sleep` on purpose: with a plain `sleep 30` the shell
# would keep the command substitution's pipe open after `timeout` killed it, and
# the probe would block for the full 30s instead of its own ceiling.
HANGING_PROBE = """#!/usr/bin/env bash
echo "$1" >> "$PROBE_LOG"
exec sleep 30
"""

HARNESS = """
set -euo pipefail
source ./lib/common.sh
SCRIPT_DIR="$FAKE_SCRIPT_DIR"
{step21}
{overrides}
rc=0
step_external_tools || rc=$?
printf 'STEP_RC=%s\\n' "$rc"
printf 'WARN_COUNT=%s\\n' "$WARN_COUNT"
printf 'FAIL_COUNT=%s\\n' "$FAIL_COUNT"
"""

# `have` is the exact decision point the step uses to pick an unpacker, so
# refusing a name here is how a host without that tool is simulated — no PATH
# surgery, and nothing the step does not really consult.
NO_UNZIP = """
have() { [[ "$1" == "unzip" ]] && return 1; command -v "$1" >/dev/null 2>&1; }
"""
NO_ZIP_READER_AT_ALL = """
have() { case "$1" in unzip|python3) return 1 ;; esac; command -v "$1" >/dev/null 2>&1; }
PYTHON_BIN=""
"""


def _w(path: Path, text: str, *, mode: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    if mode is not None:
        path.chmod(mode)
    return path


def modes_are_observable(tmp_path: Path) -> bool:
    """Does this machine record the mode `install -m` was given?

    A measurement, not a platform name. The suite normally runs on Windows/MSYS,
    where `install -D -m 0644` yields stat 755 and os.access(X_OK) is true for
    anything that exists; an assertion on the mode there passes whatever the
    installer does, which is worse than no assertion at all. On AlmaLinux the
    same command yields 644 and X_OK false, so the assertion has teeth. This
    probe uses the very command the step uses, and answers for the filesystem
    the test is about to write on.
    """
    if BASH is None:
        return False
    src = _w(tmp_path / "mode-src", "#!/usr/bin/env bash\nexit 0\n")
    dst = tmp_path / "mode-dst"
    proc = subprocess.run(
        [BASH, "-c", f'install -D -m 0644 "{src.as_posix()}" "{dst.as_posix()}"'],
        capture_output=True, text=True)
    if proc.returncode != 0 or not dst.exists():
        return False
    return (dst.stat().st_mode & 0o777) == 0o644 and not os.access(dst, os.X_OK)


def run_step21(tmp_path: Path, manifest_text: str | None, fixtures: dict[str, bytes],
               *, overrides: str = "", path_extra: list[Path] | None = None,
               env_extra: dict[str, str] | None = None) -> dict:
    script_dir = tmp_path / "deploy-copy"
    # None means: no manifest file at all — the state the repository was in.
    if manifest_text is None:
        (script_dir / "tools").mkdir(parents=True, exist_ok=True)
    else:
        _w(script_dir / "tools" / "manifest.txt", manifest_text)

    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for name, data in fixtures.items():
        (fixture_dir / name).write_bytes(data)

    fakebin = tmp_path / "fakebin"
    _w(fakebin / "curl", FAKE_CURL, mode=0o755)

    bindir = tmp_path / "usr-local-bin"
    bindir.mkdir(parents=True, exist_ok=True)

    script = _w(tmp_path / "harness.sh",
                HARNESS.format(step21=step21_source(), overrides=overrides))

    def u(p: Path) -> str:
        return str(p).replace("\\", "/")

    path_parts = [u(fakebin)] + [u(p) for p in (path_extra or [])]
    env = {
        **os.environ,
        "NO_COLOR": "1",
        "PATH": os.pathsep.join(path_parts + [os.environ["PATH"]]),
        "FAKE_SCRIPT_DIR": u(script_dir),
        "FIXTURE_DIR": u(fixture_dir),
        "TOOLS_BIN_DIR": u(bindir),
    }
    env.update(env_extra or {})

    proc = subprocess.run([BASH, u(script)], cwd=REPO / "deploy",
                          capture_output=True, text=True, timeout=180, env=env)
    return {"out": proc.stdout + proc.stderr, "bindir": bindir, "proc": proc}


def manifest_for(*entries: tuple[str, str, bytes]) -> str:
    lines = ["# a comment, which must be skipped", ""]
    for name, url, data in entries:
        lines.append(f"{name} {url} {sha256(data)}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The defect itself
# ---------------------------------------------------------------------------
def test_an_unpack_that_produces_no_binary_is_never_reported_as_installed(tmp_path):
    """This is the shipped bug, reproduced.

    The archive is a valid gzip tarball, so `tar` returns 0 — and there is no
    `trivy` inside it. The old step printed "[+] trivy installed" here and the
    operator had no way to learn otherwise. If this ever passes with a `[+]`
    again, the dashboard shows six OS updates and calls that the vulnerability
    picture, while the container, filesystem and SCA scanners silently do not
    exist.
    """
    r = run_step21(tmp_path,
                   manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ_NO_BINARY)),
                   {TRIVY_ASSET: TRIVY_TGZ_NO_BINARY})

    assert "trivy installed" not in r["out"], \
        "an empty unpack was reported as an install"
    assert "[x]" in r["out"], "nothing was reported as failed"
    assert not (r["bindir"] / "trivy").exists(), \
        "the step claims a destination file it never wrote"
    assert "1 NOT installed" in r["out"], "the closing tally hid the failure"


def test_an_archive_in_an_unknown_format_is_refused_not_announced(tmp_path):
    """A release URL that starts serving an HTML error page — a CDN outage, a
    moved asset — must produce a refusal, not a green line. With the old code
    both tar calls failed, `rm -f` succeeded, and `ok` was printed anyway."""
    r = run_step21(tmp_path,
                   manifest_for(("trivy", TRIVY_URL, NOT_AN_ARCHIVE)),
                   {TRIVY_ASSET: NOT_AN_ARCHIVE})

    assert "trivy installed" not in r["out"]
    assert "could not unpack" in r["out"]
    assert not (r["bindir"] / "trivy").exists()


def test_success_is_reported_only_after_the_binary_answers(tmp_path):
    """The positive case, and the reason the negative ones mean anything: a
    real install must still say `[+]`, and say it with the version it read off
    the host rather than the one it hoped for."""
    r = run_step21(tmp_path, manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ)),
                   {TRIVY_ASSET: TRIVY_TGZ})

    assert "[+]" in r["out"]
    assert "trivy installed: 0.74.0" in r["out"], r["out"]
    installed = r["bindir"] / "trivy"
    assert installed.exists(), "reported installed, nothing on disk"
    # The bytes of the archive member, not merely a file with the right name:
    # the old fallback `tar -xzf -C /usr/local/bin` could leave a README there
    # and nothing would have noticed.
    assert installed.read_bytes() == TRIVY_BIN.encode("utf-8"),         "the file at the destination is not the binary from the archive"
    # And nothing else from the archive was dumped next to it.
    assert not (r["bindir"] / "README.md").exists()
    assert "0 NOT installed" not in r["out"]
    assert "WARN_COUNT=0" in r["out"], r["out"]


def test_a_binary_on_disk_that_does_not_run_is_not_an_install(tmp_path):
    """Wrong architecture is the case the manifest cannot prevent: the amd64
    checksum matches, the file lands, and it cannot execute on arm64. `-x` is
    true and the tool is still unusable, so file-exists is not the proof — the
    version query is. Reported as NOT installed, and the file is left alone
    rather than deleted on a doubt."""
    broken = _targz({"trivy": "#!/usr/bin/env bash\nexit 126\n"})
    r = run_step21(tmp_path, manifest_for(("trivy", TRIVY_URL, broken)),
                   {TRIVY_ASSET: broken})

    assert "trivy installed:" not in r["out"]
    assert "does not run here" in r["out"], r["out"]
    assert "1 NOT installed" in r["out"]
    assert (r["bindir"] / "trivy").exists(), "the unproven binary was deleted"


# ---------------------------------------------------------------------------
# The zip, which is the only thing nuclei ships for Linux
# ---------------------------------------------------------------------------
def test_a_zip_release_installs(tmp_path):
    """nuclei publishes .zip and nothing else for Linux. A step that only knew
    tar could not install it on any host, ever, while reporting that it had."""
    r = run_step21(tmp_path, manifest_for(("nuclei", NUCLEI_URL, NUCLEI_ZIP)),
                   {NUCLEI_ASSET: NUCLEI_ZIP})

    assert "nuclei installed: 3.11.1" in r["out"], r["out"]
    installed = r["bindir"] / "nuclei"
    assert installed.exists()
    assert os.access(installed, os.X_OK), \
        "zip unpacking lost the executable bit and nothing put it back"


def test_a_zip_installs_on_a_host_without_unzip(tmp_path):
    """`unzip` is not in pkg_names_core, so a minimal AlmaLinux or Debian host
    may not have it. Python is (step 20 dies without one). If this path breaks,
    nuclei silently stops being installable on exactly the stripped-down hosts
    Sentinel is meant to run on."""
    python = shutil.which("python") or shutil.which("python3")
    assert python, "no python to stand in for PYTHON_BIN"

    marker = tmp_path / "python-was-used"
    wrapper = _w(tmp_path / "pywrap" / "pyshim",
                 f'#!/usr/bin/env bash\ntouch "{marker.as_posix()}"\n'
                 f'exec "{Path(python).as_posix()}" "$@"\n', mode=0o755)

    r = run_step21(tmp_path, manifest_for(("nuclei", NUCLEI_URL, NUCLEI_ZIP)),
                   {NUCLEI_ASSET: NUCLEI_ZIP}, overrides=NO_UNZIP,
                   env_extra={"PYTHON_BIN": wrapper.as_posix()})

    assert marker.exists(), "the python fallback was never reached"
    assert "nuclei installed: 3.11.1" in r["out"], r["out"]
    assert (r["bindir"] / "nuclei").read_bytes() == NUCLEI_BIN.encode("utf-8")


def test_a_host_with_no_zip_reader_says_so_instead_of_claiming_success(tmp_path):
    """Neither unzip nor python3: there is nothing that can open the archive.
    The one outcome that is not allowed is a green line, because that is how a
    scanner goes missing without a single fault being reported."""
    r = run_step21(tmp_path, manifest_for(("nuclei", NUCLEI_URL, NUCLEI_ZIP)),
                   {NUCLEI_ASSET: NUCLEI_ZIP}, overrides=NO_ZIP_READER_AT_ALL)

    assert "nuclei installed" not in r["out"]
    assert "could not unpack" in r["out"], r["out"]
    assert not (r["bindir"] / "nuclei").exists()


def test_both_formats_are_handled_in_one_pass(tmp_path):
    """The real manifest holds one of each. A step that handled only whichever
    came first would install one tool and lie about the other."""
    r = run_step21(tmp_path,
                   manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ),
                                ("nuclei", NUCLEI_URL, NUCLEI_ZIP)),
                   {TRIVY_ASSET: TRIVY_TGZ, NUCLEI_ASSET: NUCLEI_ZIP})

    assert (r["bindir"] / "trivy").exists()
    assert (r["bindir"] / "nuclei").exists()
    assert "external tools: 2 installed" in r["out"], r["out"]


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------
def test_comments_and_blank_lines_are_skipped_and_entries_are_not(tmp_path):
    """The shipped manifest is mostly a comment header. If a `#` line were ever
    read as an entry the step would try to download it; if a real entry were
    skipped as a comment the tool would go missing without a word."""
    text = (
        "# header\n"
        "#\n"
        "\n"
        "   \n"
        f"trivy {TRIVY_URL} {sha256(TRIVY_TGZ)}\n"
        "# trailing comment\n"
        "\n"
        f"nuclei {NUCLEI_URL} {sha256(NUCLEI_ZIP)}\n"
    )
    r = run_step21(tmp_path, text,
                   {TRIVY_ASSET: TRIVY_TGZ, NUCLEI_ASSET: NUCLEI_ZIP})

    assert "external tools: 2 installed, 0 already present" in r["out"], r["out"]
    assert "WARN_COUNT=0" in r["out"]
    assert "downloading #" not in r["out"]


def test_a_manifest_without_a_trailing_newline_loses_no_tool(tmp_path):
    """An editor that strips the final newline would make `read` return 1 on the
    last line, and the last tool would be skipped in total silence — no warning,
    no failure, just one scanner that is not there."""
    text = (f"trivy {TRIVY_URL} {sha256(TRIVY_TGZ)}\n"
            f"nuclei {NUCLEI_URL} {sha256(NUCLEI_ZIP)}")
    r = run_step21(tmp_path, text,
                   {TRIVY_ASSET: TRIVY_TGZ, NUCLEI_ASSET: NUCLEI_ZIP})

    assert (r["bindir"] / "nuclei").exists(), "the last entry was dropped"
    assert "external tools: 2 installed" in r["out"], r["out"]


def test_an_incomplete_entry_is_refused_rather_than_downloaded(tmp_path):
    """A line missing its checksum used to become url="" sha="", and `curl` was
    then asked to fetch nothing while `sha256sum -c` compared against an empty
    string. Refusing is the only safe reading of a half-written pin."""
    text = f"trivy {TRIVY_URL}\n"
    r = run_step21(tmp_path, text, {TRIVY_ASSET: TRIVY_TGZ})

    assert "is incomplete" in r["out"], r["out"]
    assert "trivy installed" not in r["out"]
    assert not (r["bindir"] / "trivy").exists()


def test_a_checksum_mismatch_installs_nothing(tmp_path):
    """The pin is the whole point. A mismatch means the bytes are not the ones
    reviewed in this repository, and the step must stop at that — not retry
    without verification, not install anyway."""
    text = f"trivy {TRIVY_URL} {'0' * 64}\n"
    r = run_step21(tmp_path, text, {TRIVY_ASSET: TRIVY_TGZ})

    assert "checksum mismatch" in r["out"]
    assert "trivy installed" not in r["out"]
    assert not (r["bindir"] / "trivy").exists()


def test_a_download_that_fails_is_reported_and_installs_nothing(tmp_path):
    """A 404 from a moved release must not read like a success, and must not
    leave the installer half-way through a tool."""
    r = run_step21(tmp_path, manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ)),
                   {})  # no fixture -> the fake curl 404s

    assert "download failed" in r["out"]
    assert "trivy installed" not in r["out"]
    assert not (r["bindir"] / "trivy").exists()


# ---------------------------------------------------------------------------
# Where the archive is staged
# ---------------------------------------------------------------------------
def test_the_staging_directory_is_not_a_guessable_path(tmp_path):
    """The archive is unpacked somewhere an unprivileged user cannot predict.

    What this replaced: `/tmp/sentinel-tool-${name}.tar.gz`, a fixed path in a
    world-writable directory, written and unpacked as root. Any local user could
    create that path first — as a symlink, or as a directory whose contents the
    step would then `find` a binary in — and step 21 would install it into
    /usr/local/bin with mode 0755. The tool that is supposed to find
    vulnerabilities becomes one.

    The whole suite stayed green when the fixed path was put back, which is why
    this test exists. It is a behavioural test, not a grep for `mktemp`: the
    step's staging directory is read back out of the `install` call it makes,
    and two runs of the same manifest must not land in the same place.
    """
    real_install = shutil.which("install")
    assert real_install, "no install(1) on PATH to stand behind the shim"

    shim = tmp_path / "installshim"
    _w(shim / "install", FAKE_INSTALL, mode=0o755)
    log = tmp_path / "install-src.log"

    for run in ("run1", "run2"):
        r = run_step21(tmp_path / run,
                       manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ)),
                       {TRIVY_ASSET: TRIVY_TGZ}, path_extra=[shim],
                       env_extra={"INSTALL_SRC_LOG": log.as_posix(),
                                  "REAL_INSTALL": Path(real_install).as_posix()})
        assert "trivy installed: 0.74.0" in r["out"], r["out"]

    sources = log.read_text(encoding="utf-8").split()
    assert len(sources) == 2, f"expected one install per run, got {sources}"
    staged = [str(PurePosixPath(s).parent) for s in sources]

    assert staged[0] != staged[1], (
        f"both runs staged the archive in the same directory ({staged[0]}), so "
        f"the path is predictable — a local user can create it first and hand "
        f"root a binary of their own")
    for path in staged:
        assert not path.endswith("sentinel-tool-trivy"), (
            f"the staging directory is the fixed, guessable name again: {path}")


# ---------------------------------------------------------------------------
# A tool that is already there
# ---------------------------------------------------------------------------
def test_a_tool_already_on_path_at_another_version_is_named_as_such(tmp_path):
    """`have` skips a tool already on PATH, which is right — an operator's own
    build is not ours to overwrite. The old report of it was not: "[+] trivy
    already installed" let the operator believe the pinned version was on the
    host. A 0.60 trivy reports fewer findings than 0.74 and never says why."""
    old = tmp_path / "onpath"
    _w(old / "trivy", TRIVY_BIN, mode=0o755)

    r = run_step21(tmp_path, manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ)),
                   {TRIVY_ASSET: TRIVY_TGZ}, path_extra=[old],
                   env_extra={"FAKE_TRIVY_VERSION": "0.60.0"})

    assert "0.60.0" in r["out"] and "pins 0.74.0" in r["out"], r["out"]
    assert "[!]" in r["out"], "a stale scanner was reported without a warning"
    assert "1 present but unverified" in r["out"], r["out"]
    assert "[+]" not in r["out"],         "the closing verdict went green over a build that is not the pinned one"


def test_a_tool_already_on_path_at_the_pinned_version_is_not_a_warning(tmp_path):
    """Warning about a correct host trains the operator to skip the warnings
    that matter, which is how the alerting channel stops being read."""
    old = tmp_path / "onpath"
    _w(old / "trivy", TRIVY_BIN, mode=0o755)

    r = run_step21(tmp_path, manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ)),
                   {TRIVY_ASSET: TRIVY_TGZ}, path_extra=[old],
                   env_extra={"FAKE_TRIVY_VERSION": "0.74.0"})

    assert "already installed" in r["out"] and "0.74.0" in r["out"]
    assert "WARN_COUNT=0" in r["out"], r["out"]
    assert "[+] external tools: 0 installed, 1 already present" in r["out"], r["out"]


def test_a_newer_patch_release_is_not_mistaken_for_the_pinned_one(tmp_path):
    """`3.11.10` is not `3.11.1`, and a substring test could not tell them apart.

    The comparison was `[[ "$found" != *"$pinned"* ]]`, so any version the pin
    is a PREFIX of passed as "already installed at the pinned version". nuclei
    is on the 3.11.x line right now, which makes 3.11.10 the next release but
    one — not a contrived string. Measured with a fake nuclei answering 3.11.10
    against the shipped manifest: `[+] nuclei already installed ... 3.11.10`,
    WARN_COUNT=0.

    What it costs the operator: the whole point of `tool_report_existing` is to
    say when the binary on the host is not the build whose checksum this
    repository reviewed. Reported green, an unreviewed scanner is treated as the
    reviewed one, and the version in the manifest stops describing the host.
    The same hole runs the other way — a pin of 3.11.1 against an installed
    3.11.1-dev — but the prefix direction is the one a release will produce on
    its own, without anybody touching the file.
    """
    old = tmp_path / "onpath"
    _w(old / "nuclei", NUCLEI_BIN, mode=0o755)

    r = run_step21(tmp_path, manifest_for(("nuclei", NUCLEI_URL, NUCLEI_ZIP)),
                   {NUCLEI_ASSET: NUCLEI_ZIP}, path_extra=[old],
                   env_extra={"FAKE_NUCLEI_VERSION": "3.11.10"})

    assert "reports 3.11.10, but the manifest pins 3.11.1." in r["out"], r["out"]
    assert "1 present but unverified" in r["out"], r["out"]
    assert "[+]" not in r["out"], \
        "a build that is not the pinned one closed the step green"


def test_the_version_probe_costs_three_timeouts_per_tool_not_one(tmp_path):
    """The window an operator waits through is 3 x TOOL_PROBE_TIMEOUT_S.

    Not a defect — the operator accepted the window — but the constant's comment
    named 20 seconds while the real ceiling per tool is 60, and the two-tool
    manifest can therefore sit silent for two minutes. An operator who was told
    20 reaches for Ctrl+C at 30, and a half-finished step 21 is how a host ends
    up with one scanner and a completion marker.

    Proved rather than read off the source: a binary that hangs on every flag,
    with the ceiling lowered to 1s, must be asked all three flags and must cost
    three ceilings, not one.
    """
    log = tmp_path / "probe-flags.log"
    old = tmp_path / "onpath"
    _w(old / "trivy", HANGING_PROBE, mode=0o755)

    start = time.monotonic()
    r = run_step21(tmp_path, manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ)),
                   {TRIVY_ASSET: TRIVY_TGZ}, path_extra=[old],
                   overrides="TOOL_PROBE_TIMEOUT_S=1",
                   env_extra={"PROBE_LOG": log.as_posix()})
    elapsed = time.monotonic() - start

    assert log.exists(), f"the probe never ran: {r['out']}"
    assert log.read_text(encoding="utf-8").split() == \
        ["--version", "-version", "version"], log.read_text(encoding="utf-8")
    assert elapsed >= 2.4, (
        f"one hanging tool cost {elapsed:.1f}s with a 1s ceiling, so the three "
        f"attempts are not each getting their own timeout — the constant's "
        f"comment is wrong in the other direction now")
    # And the other half of what the constant is for: bounded at all. The fake
    # binary sleeps 30s per flag, so a probe that lost its `timeout` costs 90s
    # here and hangs step 21 forever on a host with no route out — measured at
    # 100s for this file with the `timeout` removed, against 14s with it.
    assert elapsed < 20, (
        f"one hanging tool cost {elapsed:.1f}s with a 1s ceiling: the probe is "
        f"no longer bounded, so an unreachable projectdiscovery hangs the "
        f"installer instead of producing a report")
    assert "did not answer a version" in r["out"], r["out"]


def test_a_tool_on_path_that_will_not_say_its_version_is_unknown_not_fine(tmp_path):
    """"Unknown" and "fine" are different states. A binary on PATH that answers
    no version query might be anything; reporting it green is the collapse this
    repository keeps paying for."""
    old = tmp_path / "onpath"
    _w(old / "trivy", "#!/usr/bin/env bash\nexit 3\n", mode=0o755)

    r = run_step21(tmp_path, manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ)),
                   {TRIVY_ASSET: TRIVY_TGZ}, path_extra=[old])

    assert "did not answer a version" in r["out"], r["out"]
    assert "1 present but unverified" in r["out"], r["out"]
    assert "[+]" not in r["out"], "an unidentifiable binary closed the step green"


# ---------------------------------------------------------------------------
# The step's contract with the rest of the install
# ---------------------------------------------------------------------------
def test_a_missing_tool_never_stops_the_install(tmp_path):
    """Step 21 is tolerant by design: auditd, nftables and the database matter
    more than a scanner binary, and a GitHub outage must not leave a host with
    no firewall. Tolerant, but not silent — hence the counted verdict."""
    r = run_step21(tmp_path,
                   manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ_NO_BINARY),
                                ("nuclei", NUCLEI_URL, NUCLEI_ZIP)),
                   {TRIVY_ASSET: TRIVY_TGZ_NO_BINARY, NUCLEI_ASSET: NUCLEI_ZIP})

    assert "STEP_RC=0" in r["out"], "one bad tool aborted the whole install"
    assert (r["bindir"] / "nuclei").exists(), "a later tool was skipped"
    assert "1 installed" in r["out"] and "1 NOT installed" in r["out"], r["out"]


def test_the_closing_verdict_is_a_warn_so_it_reaches_the_summary(tmp_path):
    """`fail` increments FAIL_COUNT, which install.sh's summary never prints —
    only WARN_COUNT is. If the closing line stopped being a warn, a run that
    installed nothing would end with a clean-looking summary."""
    r = run_step21(tmp_path,
                   manifest_for(("trivy", TRIVY_URL, TRIVY_TGZ_NO_BINARY)),
                   {TRIVY_ASSET: TRIVY_TGZ_NO_BINARY})

    assert "WARN_COUNT=0" not in r["out"], \
        "a failed install left nothing in the end-of-run warning tally"


def test_a_missing_manifest_warns_rather_than_passing_silently(tmp_path):
    """The state this repository was actually in: no manifest, so the step
    returned 0 — and run_step then wrote the completion marker, so every later
    run skipped it as "already done". The warning is the only thing standing
    between that and an install that looks complete with no scanners on it."""
    r = run_step21(tmp_path, None, {})

    assert "no tools manifest at" in r["out"], r["out"]
    assert "[!]" in r["out"], "a step that installed nothing said nothing"
    assert "WARN_COUNT=1" in r["out"]
    assert "STEP_RC=0" in r["out"], "a missing manifest aborted the install"
    assert "[+]" not in r["out"], "installing nothing was reported green"


@pytest.mark.parametrize("manifest_text", [
    pytest.param("", id="zero-bytes"),
    pytest.param("# doar comentarii\n#\n\n   \n", id="comments-only"),
    pytest.param("#\n", id="a-single-hash"),
])
def test_a_manifest_that_pins_no_tool_never_closes_the_step_green(tmp_path, manifest_text):
    """The door next to the one that was closed on 10 August 2026.

    The missing-file case warns. A file that is PRESENT and pins nothing did
    not: the loop runs zero times, all four counters stay 0, and the closing
    verdict — "green unless something was bad or unproven" — is vacuously true
    over an empty set. Measured on the host with the shipped block, before this
    change: `[+] external tools: 0 installed, 0 already present`, STEP_RC=0,
    WARN_COUNT=0.

    What that costs the operator: `run_step` then writes the
    `21_external_tools` marker, so every later run prints "already done" and
    skips the step. The install reads as complete, `/selfcheck` has no scanner
    to miss, and the dashboard's vulnerability picture is `dnf updateinfo` and
    nothing else — with no line anywhere saying Trivy and nuclei were never
    installed. A truncating editor, a bad merge that keeps the header and drops
    the two entries, or a `> manifest.txt` is all it takes.
    """
    r = run_step21(tmp_path, manifest_text, {})

    assert "[+]" not in r["out"], \
        "a manifest that pins nothing closed the step with a green line"
    assert "0 installed, 0 already present" not in r["out"], \
        "the old vacuous verdict is back"
    assert "pins no tools" in r["out"], r["out"]
    assert "[!]" in r["out"], "a step that installed nothing said nothing"
    assert "WARN_COUNT=1" in r["out"], r["out"]
    # Still tolerant: an empty manifest must not abort auditd and nftables.
    assert "STEP_RC=0" in r["out"], r["out"]


def test_the_installed_binary_carries_the_mode_it_was_given(tmp_path):
    """A binary written 0644 is not installed, it is just present.

    The effect, where the machine records one. `install -D -m 0755` is what puts
    the executable bit on a file that came out of a zip without it — python's
    `zipfile` drops it — and a scanner that cannot be executed produces no
    findings while the dashboard shows a vulnerability page that looks answered.

    Behind a runtime probe, not behind `os.name`. Measured on Windows/MSYS,
    `install -D -m 0644` reads back as 755 and os.access(X_OK) is true for any
    file that exists, so the assertion would pass whatever the step did; on
    AlmaLinux the same command reads back 644 with X_OK false. The probe writes
    0644 with the step's own command and reads it back, so the test runs exactly
    where it can fail and says so where it cannot.
    """
    if not modes_are_observable(tmp_path / "probe"):
        pytest.skip("install -m nu lasă modul pe mașina asta; aserțiunea ar "
                    "trece orice, deci n-ar păzi nimic")

    r = run_step21(tmp_path, manifest_for(("nuclei", NUCLEI_URL, NUCLEI_ZIP)),
                   {NUCLEI_ASSET: NUCLEI_ZIP})

    installed = r["bindir"] / "nuclei"
    assert installed.exists(), r["out"]
    assert installed.stat().st_mode & 0o777 == 0o755, (
        f"the installed scanner is mode "
        f"{installed.stat().st_mode & 0o777:04o}, not 0755")
    assert os.access(installed, os.X_OK)


def test_the_binary_is_installed_executable():
    """The same failure, asserted on the shipped text so a Windows run sees it.

    Weaker than the test above — it reads the source rather than the effect —
    and kept because the effect is unobservable on the machine this suite
    usually runs on, where the test above skips. Between them, a 0755 mutated to
    0644 is caught on both platforms.

    On a real host the effect is checked twice more by the step itself: `[[ -x ]]`
    and then a version probe, which cannot succeed on a file that will not run.
    """
    body = step21_source()
    assert 'install -D -m 0755 "$src" "${TOOLS_BIN_DIR}/${name}"' in body,         "the destination file is no longer written with mode 0755"
    # And the mode is not left to a chmod that a `|| true` can swallow, which is
    # how the original lost it. Code lines only — the step's comments discuss
    # the old chmod on purpose, and matching those would make this assert on
    # prose rather than on what runs.
    code = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if "chmod" in ln],         "the mode is set by chmod again; `install -m` cannot be silently skipped"


def test_the_default_destination_is_usr_local_bin():
    """TOOLS_BIN_DIR exists so the tests above can run the shipped step against
    a temporary directory. If its default ever drifts, every test here would go
    on passing while the installer wrote binaries somewhere not on PATH."""
    assert 'TOOLS_BIN_DIR="${TOOLS_BIN_DIR:-/usr/local/bin}"' in step21_source()


# ---------------------------------------------------------------------------
# The manifest that ships
# ---------------------------------------------------------------------------
def parsed_manifest() -> dict[str, tuple[str, str]]:
    entries = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        assert len(parts) == 3, f"malformed manifest line: {line}"
        entries[parts[0]] = (parts[1], parts[2])
    return entries


def test_the_shipped_manifest_pins_the_sums_the_operator_verified():
    """These two sums were read from the projects' published checksum files on
    26 August 2026 and are what makes tomorrow's download provably the same
    bytes as today's. An accidental edit — a rebase, a stray character, a
    "helpful" version bump without a new sum — must break the build here rather
    than on the host, where it becomes a refused install at 3 a.m."""
    entries = parsed_manifest()
    assert entries["trivy"] == (
        "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/"
        "trivy_0.74.0_Linux-64bit.tar.gz",
        "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
    )
    assert entries["nuclei"] == (
        "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/"
        "nuclei_3.11.1_linux_amd64.zip",
        "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
    )


def test_every_pinned_sum_is_a_full_sha256():
    """A sum short by one character can never match, so the tool can never
    install — and the only symptom is a refusal the operator reads as a
    compromised mirror."""
    for name, (_url, sha) in parsed_manifest().items():
        assert re.fullmatch(r"[0-9a-f]{64}", sha), f"{name}: not a sha256: {sha}"


def test_the_manifest_url_and_the_pinned_version_agree():
    """The step reads the pinned version out of the URL to tell the operator
    when the host has a different build. A URL whose version no longer matches
    its asset name makes that report wrong in both directions."""
    for name, (url, _sha) in parsed_manifest().items():
        m = re.search(r"/download/v([0-9][0-9.]*)/", url)
        assert m, f"{name}: URL is not a GitHub release download URL: {url}"
        assert m.group(1) in url.rsplit("/", 1)[1], \
            f"{name}: asset name does not carry version {m.group(1)}"


def test_the_architecture_limit_is_written_down():
    """The manifest has no architecture column and both sums are amd64. On
    arm64 the install refuses, which is correct and completely opaque unless the
    reason is in the file the operator is looking at."""
    text = MANIFEST.read_text(encoding="utf-8")
    assert "x86_64" in text and "arm64" in text
    assert "ARHITECTURA" in text.upper()


def test_the_manifest_has_no_cr_bytes():
    """A CR at the end of a manifest line becomes part of the checksum string,
    `sha256sum -c` never matches, and the operator is told about a compromised
    mirror that does not exist."""
    assert b"\r" not in MANIFEST.read_bytes()
