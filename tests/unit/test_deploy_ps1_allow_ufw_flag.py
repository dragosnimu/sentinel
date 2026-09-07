"""`-AllowUfw` / `-AllowFirewalld` on the PowerShell twin — same plumbing gap
as `scripts/deploy.sh`, checked separately because the two scripts are
independent implementations that must not drift apart in behaviour (see
deploy.ps1's own `.DESCRIPTION`).

Same shape as the ps1 checks in tests/unit/test_deploy_secrets_flag.py and
tests/security/test_secrets_rotation_guard.py: the shipped fragment is cut out
of deploy.ps1 verbatim and run under real PowerShell with the two call sites
(`Invoke-SshLive` for the --dry-run preflight call, `$installArgs` for a real
install) replaced by something that records what it received — the decision
an operator's `-AllowUfw` actually produces, not a string near it in the
source.
"""

from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEPLOY_PS1 = REPO / "scripts" / "deploy.ps1"

PS = shutil.which("powershell.exe") or shutil.which("pwsh")

pytestmark = pytest.mark.skipif(PS is None, reason="no PowerShell available")


def _ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True)


def _text() -> str:
    return DEPLOY_PS1.read_text(encoding="utf-8-sig")


# ---------------------------------------------------------------------------
# The -DryRun preflight command line
# ---------------------------------------------------------------------------
def _dry_run_fragment() -> str:
    text = _text()
    start_marker = "$domainArg = if ($Domain) { \"--domain '$Domain'\" } else { '' }"
    start = text.index(start_marker)
    end_marker = ("Invoke-SshLive -Tty -Command \"sudo '$remoteDir/deploy/preflight.sh' "
                  "$domainArg --web-port $WebPort --nginx-mode $NginxMode $adminArg "
                  "$ufwArg $firewalldArg\"")
    end = text.index(end_marker, start) + len(end_marker)
    fragment = text[start:end]
    assert "AllowUfw" in fragment
    assert "AllowFirewalld" in fragment
    return fragment


@pytest.mark.parametrize("allow_ufw,allow_firewalld,expect_ufw,expect_fw", [
    ("$true", "$false", True, False),
    ("$false", "$true", False, True),
    ("$true", "$true", True, True),
    ("$false", "$false", False, False),
])
def test_dry_run_preflight_call_carries_the_flags_when_set(
        allow_ufw, allow_firewalld, expect_ufw, expect_fw):
    """The failure this prevents: -AllowUfw parses without error and the
    preflight call on the server never sees it, so the operator gets refused
    anyway with no indication the flag did nothing."""
    fragment = _dry_run_fragment()
    script = "\n".join([
        "function Invoke-SshLive { param([switch]$Tty, [string]$Command) Write-Host \"CMD:$Command\" }",
        "$remoteDir = '/opt/sentinel-deploy'",
        "$Domain = $null",
        "$WebPort = 8443",
        "$NginxMode = 'dedicated'",
        "$AdminIp = $null",
        f"$AllowUfw = {allow_ufw}",
        f"$AllowFirewalld = {allow_firewalld}",
        fragment,
    ])
    proc = _ps(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    line = next(l for l in proc.stdout.splitlines() if l.startswith("CMD:"))
    assert ("--allow-ufw" in line) == expect_ufw, line
    assert ("--allow-firewalld" in line) == expect_fw, line


# ---------------------------------------------------------------------------
# $installArgs — the real-install path
# ---------------------------------------------------------------------------
def _install_args_fragment() -> str:
    text = _text()
    start_marker = ('$installArgs = @("--nginx-mode $NginxMode", '
                     '"--web-port $WebPort", "--cert-mode $CertMode")')
    start = text.index(start_marker)
    end_marker = "if ($AllowFirewalld) { $installArgs += '--allow-firewalld' }"
    end = text.index(end_marker, start) + len(end_marker)
    fragment = text[start:end]
    assert "AllowUfw" in fragment
    return fragment


@pytest.mark.parametrize("allow_ufw,allow_firewalld,expect_ufw,expect_fw", [
    ("$true", "$false", True, False),
    ("$false", "$true", False, True),
    ("$true", "$true", True, True),
    ("$false", "$false", False, False),
])
def test_install_args_carries_the_flags_when_set(
        allow_ufw, allow_firewalld, expect_ufw, expect_fw):
    """Twin of the dry-run test for a real install: a re-run that needs
    -AllowUfw must not have it silently dropped between deploy.ps1 and the
    remote install.sh invocation."""
    fragment = _install_args_fragment()
    script = "\n".join([
        "$NginxMode = 'dedicated'",
        "$WebPort = 8443",
        "$CertMode = 'auto'",
        "$AdminIp = $null",
        "$Domain = $null",
        "$Email = $null",
        "$DbPort = $null",
        "$FromStep = $null",
        "$forceStepList = ''",
        f"$AllowUfw = {allow_ufw}",
        f"$AllowFirewalld = {allow_firewalld}",
        fragment,
        '$installArgs | ForEach-Object { Write-Host "ARG:$_" }',
    ])
    proc = _ps(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    args = [l[len("ARG:"):] for l in proc.stdout.splitlines() if l.startswith("ARG:")]
    assert ("--allow-ufw" in args) == expect_ufw, args
    assert ("--allow-firewalld" in args) == expect_fw, args


def test_the_flags_are_declared_parameters():
    """A -AllowUfw that Get-Help does not know about is a flag an operator
    cannot discover — PowerShell would refuse it outright as an unknown
    parameter before this fragment ever runs."""
    text = _text()
    assert "[switch]$AllowUfw" in text
    assert "[switch]$AllowFirewalld" in text


# ---------------------------------------------------------------------------
# $resumeCmd — printed after a failed real install, as the -FromStep and
# -Rollback hint.
#
# -FromStep only skips steps BELOW it, so a resume re-runs step 1 (preflight)
# exactly like the original attempt. If that attempt needed -AllowUfw to get
# past the ufw check, the printed resume command needs it too, or the
# operator copies it verbatim and is refused by the same check again.
# ---------------------------------------------------------------------------
def _resume_cmd_fragment() -> str:
    text = _text()
    start_marker = "$keyArg    = ''"
    start = text.index(start_marker)
    end_marker = ('$resumeCmd = ".\\scripts\\deploy.ps1 -HostName $HostName '
                  '-User $User$keyArg$ufwResumeArg$firewalldResumeArg"')
    end = text.index(end_marker, start) + len(end_marker)
    fragment = text[start:end]
    assert "AllowUfw" in fragment
    assert "AllowFirewalld" in fragment
    return fragment


@pytest.mark.parametrize("allow_ufw,allow_firewalld,expect_ufw,expect_fw", [
    ("$true", "$false", True, False),
    ("$false", "$true", False, True),
    ("$false", "$false", False, False),
])
def test_resume_cmd_carries_the_flags_when_set(
        allow_ufw, allow_firewalld, expect_ufw, expect_fw):
    """The failure this prevents: an install that needed -AllowUfw fails
    partway, the operator runs the printed `$resumeCmd -FromStep <N>`
    verbatim, and preflight refuses again on the exact same ufw check
    because the resume hint never carried the flag that got past it the
    first time."""
    fragment = _resume_cmd_fragment()
    script = "\n".join([
        "$HostName = 'host.example.invalid'",
        "$User = 'deploy'",
        "$Key = $null",
        f"$AllowUfw = {allow_ufw}",
        f"$AllowFirewalld = {allow_firewalld}",
        fragment,
        "Write-Host \"RESUME:$resumeCmd\"",
    ])
    proc = _ps(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    line = next(l for l in proc.stdout.splitlines() if l.startswith("RESUME:"))
    assert ("-AllowUfw" in line) == expect_ufw, line
    assert ("-AllowFirewalld" in line) == expect_fw, line
