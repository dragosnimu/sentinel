"""`--allow-ufw` / `--allow-firewalld` have to reach the SERVER, not just be
accepted on the command line.

Measured 7 Sep 2026 on the second production host (Ubuntu 24.04.4): both
flags existed in `deploy/preflight.sh` and `deploy/install.sh`, but
`scripts/deploy.sh`'s standalone `--dry-run` preflight call and its
`INSTALL_ARGS` for a real install had neither — the documented escape hatch
was unreachable from the only sanctioned deployment path. Passing it on the
`deploy.sh` command line would have parsed cleanly and then been silently
dropped on the floor at the two points that actually build the remote
command: the operator would type `--allow-ufw`, see no error, and still get
refused by preflight.

These tests run the two SHIPPED forwarding lines under bash, with `ssh_sudo`
and the install command line replaced by a function that records what it was
called with — the same effect-not-intent test as everywhere else in this
suite: it does not check that the string `--allow-ufw` appears near
`ALLOW_UFW` in the source, it checks that the array/string a stubbed remote
call actually receives contains the flag.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
DEPLOY = DEPLOY_SH.read_text(encoding="utf-8")
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="no bash on PATH")


def _env(**extra: str) -> dict[str, str]:
    return {**os.environ, "NO_COLOR": "1", **extra}


def _run(script: str) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                          env=_env())


# ---------------------------------------------------------------------------
# The --dry-run preflight command line
# ---------------------------------------------------------------------------
def _preflight_forward_line() -> str:
    """The `ssh_sudo "..."` call at the heart of the --dry-run branch, exact
    bytes. Index-based, not regexed: the line is one long double-quoted
    string full of `'...'` and `${VAR:+...}` — a regex built to match it would
    just be a second, less trustworthy copy of the line itself."""
    marker = "ssh_sudo \"'${REMOTE_DIR}/deploy/preflight.sh'"
    start = DEPLOY.index(marker)
    end = DEPLOY.index("\n", start)
    line = DEPLOY[start:end]
    assert line.endswith('"'), "extragerea a ratat sfârșitul liniei"
    return line


@pytest.mark.parametrize("allow_ufw,allow_firewalld,expect_ufw,expect_fw", [
    ("1", "", True, False),
    ("", "1", False, True),
    ("1", "1", True, True),
    ("", "", False, False),
])
def test_preflight_dry_run_call_carries_the_flags_when_set(
        allow_ufw, allow_firewalld, expect_ufw, expect_fw):
    """The failure this prevents: an operator passes --allow-ufw to deploy.sh,
    sees no error, and preflight refuses anyway because the flag never
    reached the remote command line — the escape hatch existed on paper and
    nowhere else."""
    line = _preflight_forward_line()
    script = "\n".join([
        "set -u",
        "ssh_sudo() { printf 'CMD:%s\\n' \"$1\"; }",
        "REMOTE_DIR=/opt/sentinel-deploy",
        'DOMAIN=""',
        "WEB_PORT=8443",
        "NGINX_MODE=dedicated",
        'ADMIN_IP=""',
        f'ALLOW_UFW="{allow_ufw}"',
        f'ALLOW_FIREWALLD="{allow_firewalld}"',
        line,
    ])
    proc = _run(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cmd = next(l for l in proc.stdout.splitlines() if l.startswith("CMD:"))
    assert ("--allow-ufw" in cmd) == expect_ufw, cmd
    assert ("--allow-firewalld" in cmd) == expect_fw, cmd


# ---------------------------------------------------------------------------
# INSTALL_ARGS — the real-install path
# ---------------------------------------------------------------------------
def _install_args_fragment() -> str:
    """The full INSTALL_ARGS assembly, from its first line to the --yes
    forwarding, exact bytes — not retyped, for the same reason
    test_deploy_secrets_flag.py's _secrets_missing_fragment gives: a
    reimplementation can pass while the shipped code silently drops a flag."""
    start_marker = 'INSTALL_ARGS=(--nginx-mode "$NGINX_MODE"'
    start = DEPLOY.index(start_marker)
    end_marker = "(( ASSUME_YES )) && INSTALL_ARGS+=(--yes)\n"
    end = DEPLOY.index(end_marker, start) + len(end_marker)
    fragment = DEPLOY[start:end]
    assert "--allow-ufw" in fragment
    assert "--allow-firewalld" in fragment
    return fragment


@pytest.mark.parametrize("allow_ufw,allow_firewalld,expect_ufw,expect_fw", [
    ("1", "", True, False),
    ("", "1", False, True),
    ("1", "1", True, True),
    ("", "", False, False),
])
def test_install_args_carries_the_flags_when_set(
        allow_ufw, allow_firewalld, expect_ufw, expect_fw):
    """Twin of the dry-run test for a REAL install: a rerun that needs
    --allow-ufw (the port is meant to stay closed behind an ssh tunnel, say)
    must not have the flag silently dropped between deploy.sh and the remote
    install.sh invocation."""
    fragment = _install_args_fragment()
    script = "\n".join([
        "set -u",
        "NGINX_MODE=dedicated",
        "WEB_PORT=8443",
        "CERT_MODE=auto",
        'ADMIN_IP=""',
        'DOMAIN=""',
        'EMAIL=""',
        'DB_PORT=""',
        'FROM_STEP=""',
        'FORCE_STEP=""',
        f'ALLOW_UFW="{allow_ufw}"',
        f'ALLOW_FIREWALLD="{allow_firewalld}"',
        "ASSUME_YES=0",
        fragment,
        'printf "%s\\n" "${INSTALL_ARGS[@]}"',
    ])
    proc = _run(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    args = proc.stdout.splitlines()
    assert ("--allow-ufw" in args) == expect_ufw, args
    assert ("--allow-firewalld" in args) == expect_fw, args


def test_the_flags_are_documented_in_the_help_header():
    """A flag deploy.sh silently accepts but never explains is worse than one
    it refuses outright — the operator has no way to discover it exists."""
    assert "--allow-ufw" in DEPLOY
    assert "--allow-firewalld" in DEPLOY


# ---------------------------------------------------------------------------
# The `while [[ $# -gt 0 ]]; do ... done` argument-parsing loop itself.
#
# Every test above pre-sets ALLOW_UFW/ALLOW_FIREWALLD by hand before running
# the two forwarding fragments — which proves those fragments forward the
# variables correctly, but says nothing about whether `--allow-ufw)` on the
# actual command line still SETS those variables. A mutation that made
# `--allow-ufw)` set ALLOW_FIREWALLD instead (or nothing at all) would leave
# every test above green.
# ---------------------------------------------------------------------------
def _arg_parse_block() -> str:
    """The parsing loop, exact bytes — same extraction and same immediate
    self-check as `_arg_parse_block()` in tests/security/test_preflight_ufw.py
    for preflight.sh's own loop: an extractor that stops halfway would run a
    truncated shell, and every test below would pass for the wrong reason."""
    lines = DEPLOY.splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.strip() == "while [[ $# -gt 0 ]]; do")
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "done")
    block = "\n".join(lines[start:end + 1])
    assert "--allow-ufw)" in block, "the extraction missed --allow-ufw parsing"
    assert "--allow-firewalld)" in block
    return block + "\n"


@pytest.mark.parametrize("cli_args,expect_ufw,expect_fw", [
    ("--allow-ufw", "1", ""),
    ("--allow-firewalld", "", "1"),
    ("--allow-ufw --allow-firewalld", "1", "1"),
    ("", "", ""),
])
def test_allow_ufw_flag_sets_only_its_own_variable_when_parsed_from_argv(
        cli_args, expect_ufw, expect_fw):
    """The failure this prevents: `--allow-ufw)` mutated to set
    ALLOW_FIREWALLD (or to a no-op) — an operator types --allow-ufw, deploy.sh
    parses it without complaint, and the variable that the forwarding lines
    actually read (proven correct above) was never set from the one place an
    operator's argv reaches it."""
    block = _arg_parse_block()
    script = "\n".join([
        "set -u",
        "die() { printf 'DIE:%s\\n' \"$*\" >&2; exit 1; }",
        "usage() { exit 0; }",
        'HOST=""; USER=""; KEY=""; DOMAIN=""; EMAIL=""; ADMIN_IP=""; DB_PORT=""; SECRETS_ARG=""',
        "ALLOW_ROTATION_ALL=0",
        'ALLOW_ROTATION_KEYS=""',
        "SSH_PORT=22",
        "WEB_PORT=8443",
        "CERT_MODE=auto",
        "NGINX_MODE=dedicated",
        'DRY_RUN=0; ROLLBACK=0; PURGE=0; FROM_STEP=""; FORCE_STEP=""; ASSUME_YES=0',
        'ALLOW_UFW=""; ALLOW_FIREWALLD=""',
        f"set -- {cli_args}",
        block,
        'printf "ALLOW_UFW=%s\\n" "$ALLOW_UFW"',
        'printf "ALLOW_FIREWALLD=%s\\n" "$ALLOW_FIREWALLD"',
    ])
    proc = _run(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    got_ufw = next(l for l in proc.stdout.splitlines()
                   if l.startswith("ALLOW_UFW=")).split("=", 1)[1]
    got_fw = next(l for l in proc.stdout.splitlines()
                  if l.startswith("ALLOW_FIREWALLD=")).split("=", 1)[1]
    assert got_ufw == expect_ufw, proc.stdout
    assert got_fw == expect_fw, proc.stdout


# ---------------------------------------------------------------------------
# The resume hint printed after a failed real install.
#
# `--from-step <N>` only skips steps BELOW N (see test_force_step_list.py's
# module docstring for the outage this convention exists to prevent), so an
# operator resuming after an unrelated failure re-runs step 1 (preflight)
# exactly like the first attempt. If that attempt needed --allow-ufw to get
# past the ufw check, the resume command needs it too, or the operator copies
# the printed hint verbatim and hits the same refusal a second time.
# ---------------------------------------------------------------------------
def _resume_hint_fragment() -> str:
    marker = 'warn "The installer is step-numbered and idempotent. Fix the cause, then resume:"'
    start = DEPLOY.index(marker)
    end_marker = 'warn "Or undo everything:"'
    end = DEPLOY.index(end_marker, start)
    fragment = DEPLOY[start:end]
    assert "--allow-ufw" in fragment, "the resume hint dropped --allow-ufw"
    assert "--allow-firewalld" in fragment
    return fragment


@pytest.mark.parametrize("allow_ufw,allow_firewalld,expect_ufw,expect_fw", [
    ("1", "", True, False),
    ("", "1", False, True),
    ("", "", False, False),
])
def test_the_resume_hint_after_a_failed_install_carries_the_flags(
        allow_ufw, allow_firewalld, expect_ufw, expect_fw):
    """The failure this prevents: a deploy that needed --allow-ufw fails
    partway for an unrelated reason, the operator copies the printed resume
    command, and it is refused again by the SAME ufw check — because the
    hint that told them what to type next forgot the flag that got them past
    it the first time."""
    fragment = _resume_hint_fragment()
    script = "\n".join([
        "set -u",
        "warn() { printf 'WARN:%s\\n' \"$*\"; }",
        "HOST=host.example.invalid", "USER=deploy", 'KEY=""', 'DOMAIN=""',
        f'ALLOW_UFW="{allow_ufw}"',
        f'ALLOW_FIREWALLD="{allow_firewalld}"',
        fragment,
    ])
    proc = _run(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert ("--allow-ufw" in out) == expect_ufw, out
    assert ("--allow-firewalld" in out) == expect_fw, out
