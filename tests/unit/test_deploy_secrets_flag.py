"""`--secrets` has to mean the file the operator named, not the default one.

Without a per-host path, the operator kept ONE `secrets/.env.local` and
renamed a per-host copy into place by hand before every deploy. On
2026-09-05 that convention failed twice on the same day: the active file was
a mixture of one host's Telegram bot token and another host's database
password, and the per-host fallback kept as backup was three weeks stale and
differed from the live host on six keys, `SENTINEL_BEACON_SECRET` among them
— rotating it would have made the external witness reject every signal as a
bad one.

`--secrets <path>` lets the operator point at `secrets/.env.local.<host>`
directly, no renaming. These tests cover the RESOLUTION of that flag — which
path ends up in `$SECRETS_FILE`, what happens when it is missing, and now
also whether `--dry-run` changes any of that:

  * omitted and missing, real run   -> exactly today's behaviour, falls
                                        through to scripts/secrets-init.sh
  * given explicitly and missing    -> a hard stop, secrets-init.sh is NEVER
                                        run — on a real run AND on --dry-run,
                                        because a misspelled path must fail a
                                        rehearsal too, not just the real run
                                        that follows it
  * omitted and missing, --dry-run  -> tolerated: a first install must still
                                        be able to rehearse, and nothing here
                                        invents a file for it to read

The second one is the point of the whole change: a name given on purpose must
never be silently replaced by a freshly generated file, because that file
would carry a brand-new SENTINEL_DB_PASSWORD and no SENTINEL_BEACON_SECRET at
all — exactly the rotation-by-accident this flag exists to close.

The comparison against the host itself (compare_secrets_with_host / its
--dry-run report-only behaviour, and --allow-rotation) is exercised in
tests/security/test_secrets_rotation_guard.py; this file stops at "which file
gets used", not "what happens once it is read".
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
DEPLOY_PS1 = REPO / "scripts" / "deploy.ps1"

BASH = shutil.which("bash")


def _env(**extra: str) -> dict[str, str]:
    """The caller's environment plus the overrides — see test_deploy_key_default.py
    for why this is not built from scratch (WSL bash vs Git Bash on PATH)."""
    return {**os.environ, "NO_COLOR": "1", **extra}


def _fragment(pattern: str) -> str:
    """A piece cut verbatim out of deploy.sh, not retyped here."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    m = re.search(pattern, text, re.S | re.M)
    assert m, f"fragment not found in deploy.sh: {pattern}"
    return m.group(0)


# ---------------------------------------------------------------------------
# bash: resolution of $SECRETS_FILE from --secrets / $SECRETS_ARG
# ---------------------------------------------------------------------------
def _resolve(tmp_path: Path, secrets_arg: str = "") -> subprocess.CompletedProcess:
    """The shipped resolution line, run against a fabricated $SECRETS_ARG."""
    line = _fragment(r'^\[\[ -n "\$SECRETS_ARG" \]\] && SECRETS_FILE="\$SECRETS_ARG"$')
    script = "\n".join([
        f'REPO_ROOT="{str(tmp_path).replace(chr(92), "/")}"',
        'SECRETS_FILE="${REPO_ROOT}/secrets/.env.local"',
        f'SECRETS_ARG="{secrets_arg}"',
        line,
        'printf "SECRETS_FILE=%s\\n" "$SECRETS_FILE"',
    ])
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, env=_env())


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_omitted_flag_keeps_the_default_path(tmp_path):
    """No --secrets at all must be byte-identical to today: secrets/.env.local."""
    proc = _resolve(tmp_path)
    assert proc.returncode == 0, proc.stderr
    expected = f"{tmp_path}/secrets/.env.local".replace("\\", "/")
    assert f"SECRETS_FILE={expected}" in proc.stdout.replace("\\", "/")


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_an_explicit_secrets_path_replaces_the_default(tmp_path):
    """--secrets secrets/.env.local.host2 must be used AS GIVEN, not merged with
    or ignored in favour of the default path."""
    given = str(tmp_path / "secrets" / ".env.local.host2").replace("\\", "/")
    proc = _resolve(tmp_path, secrets_arg=given)
    assert proc.returncode == 0, proc.stderr
    assert f"SECRETS_FILE={given}" in proc.stdout.replace("\\", "/")


# ---------------------------------------------------------------------------
# bash: the missing-file branches — the actual safety property
# ---------------------------------------------------------------------------
# Two separate `if` statements in the shipped script, back to back: the named-
# and-missing hard stop (runs on --dry-run too), then the default-missing
# fall-through (secrets-init.sh only on a real run). Cut as ONE fragment,
# verbatim, string-indexed rather than regexed — the second block nests an
# `if ($DryRun) ... else ... fi` inside it, and a naive non-greedy regex
# anchored on the first bare `fi` would stop at that INNER one and silently
# test half the shipped code. See tests/security/test_secrets_rotation_guard.py's
# _fragment() for the same lesson learned the same way.
def _secrets_missing_fragment() -> str:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start_marker = 'if [[ -n "$SECRETS_ARG" && ! -f "$SECRETS_FILE" ]]; then\n'
    start = text.index(start_marker)
    end_marker = ('"${REPO_ROOT}/scripts/secrets-init.sh" || die "secret initialisation failed"\n'
                  '    fi\n'
                  'fi\n')
    end = text.index(end_marker, start) + len(end_marker)
    fragment = text[start:end]
    assert "secrets-init.sh" in fragment
    assert "DRY_RUN" in fragment
    return fragment


HARNESS = """
set -u
info() {{ printf 'INFO %s\\n' "$*"; }}
warn() {{ printf 'WARN %s\\n' "$*" >&2; }}
die()  {{ printf 'ERR %s\\n' "$*" >&2; exit 1; }}

REPO_ROOT="{repo_root}"
SECRETS_FILE="{secrets_file}"
SECRETS_ARG="{secrets_arg}"
DRY_RUN={dry_run}

{fragment}
printf 'REACHED_END\\n'
"""


def _run_missing_branch(tmp_path: Path, secrets_arg: str, secrets_file: str,
                        dry_run: int = 0) -> subprocess.CompletedProcess:
    fragment = _secrets_missing_fragment()

    fake_repo = tmp_path / "repo"
    (fake_repo / "scripts").mkdir(parents=True)
    marker = fake_repo / "scripts" / "secrets-init-ran.marker"
    # Stands in for the real secrets-init.sh: records that it ran, and would
    # normally prompt/generate. It must never execute for an explicit --secrets,
    # nor for a --dry-run (a rehearsal must not invent a file to read).
    (fake_repo / "scripts" / "secrets-init.sh").write_text(
        f'#!/usr/bin/env bash\ntouch "{marker.as_posix()}"\n',
        encoding="utf-8", newline="\n",
    )
    (fake_repo / "scripts" / "secrets-init.sh").chmod(0o755)

    script = HARNESS.format(
        repo_root=fake_repo.as_posix(),
        secrets_file=secrets_file,
        secrets_arg=secrets_arg,
        dry_run=dry_run,
        fragment=fragment,
    )
    script_path = tmp_path / "harness.sh"
    script_path.write_text(script, encoding="utf-8", newline="\n")
    proc = subprocess.run([BASH, script_path.as_posix()], capture_output=True,
                          text=True, env=_env())
    proc.marker_ran = marker.exists()  # type: ignore[attr-defined]
    return proc


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_omitted_and_missing_falls_through_to_secrets_init(tmp_path):
    """Today's behaviour, unchanged on a real run: no --secrets, no file ->
    secrets-init.sh runs."""
    missing = (tmp_path / "secrets" / ".env.local").as_posix()
    proc = _run_missing_branch(tmp_path, secrets_arg="", secrets_file=missing, dry_run=0)
    assert proc.returncode == 0, proc.stderr
    assert "REACHED_END" in proc.stdout
    assert proc.marker_ran, "secrets-init.sh was not invoked for the omitted, missing case"


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_explicit_and_missing_dies_without_running_secrets_init(tmp_path):
    """The failure this flag exists to close: naming a file that does not exist
    must never fall through to generating a fresh one under its name — that
    fresh file would carry a brand-new SENTINEL_DB_PASSWORD and no
    SENTINEL_BEACON_SECRET, and deploying it would rotate both silently."""
    named = (tmp_path / "secrets" / ".env.local.host2").as_posix()
    proc = _run_missing_branch(tmp_path, secrets_arg=named, secrets_file=named, dry_run=0)
    assert proc.returncode != 0, "an explicitly named missing file did not stop the run"
    assert "REACHED_END" not in proc.stdout
    assert not proc.marker_ran, "secrets-init.sh ran for an explicitly named file"
    assert "--secrets" in proc.stderr
    assert named in proc.stderr or "file not found" in proc.stderr


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_a_present_file_is_untouched_whether_named_or_default(tmp_path):
    """The branch must be a no-op once the file exists — an existing file is
    neither regenerated nor complained about, named or not."""
    present = tmp_path / "secrets" / ".env.local.host2"
    present.parent.mkdir(parents=True)
    present.write_text("SENTINEL_DB_PASSWORD=x\n", encoding="utf-8", newline="\n")
    proc = _run_missing_branch(tmp_path, secrets_arg=present.as_posix(),
                               secrets_file=present.as_posix(), dry_run=0)
    assert proc.returncode == 0, proc.stderr
    assert "REACHED_END" in proc.stdout
    assert not proc.marker_ran


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_explicit_and_missing_dies_even_on_dry_run(tmp_path):
    """A misspelled --secrets path must fail a --dry-run rehearsal too, not
    only the real run that follows it — that gap is exactly what let the
    recorded production invocation ([--dry-run] as its usual flag) rehearse a
    typo as "preflight OK" before this fix."""
    named = (tmp_path / "secrets" / ".env.local.host2").as_posix()
    proc = _run_missing_branch(tmp_path, secrets_arg=named, secrets_file=named, dry_run=1)
    assert proc.returncode != 0, "a --dry-run with a named missing file did not stop"
    assert "REACHED_END" not in proc.stdout
    assert not proc.marker_ran
    assert "--secrets" in proc.stderr


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_omitted_and_missing_tolerated_on_dry_run(tmp_path):
    """A first install has no secrets.env.local yet. A --dry-run must still be
    able to rehearse it — and must not invent one by running secrets-init.sh,
    which is a real-run-only action."""
    missing = (tmp_path / "secrets" / ".env.local").as_posix()
    proc = _run_missing_branch(tmp_path, secrets_arg="", secrets_file=missing, dry_run=1)
    assert proc.returncode == 0, proc.stderr
    assert "REACHED_END" in proc.stdout
    assert not proc.marker_ran, "secrets-init.sh ran during a --dry-run"
    assert "dry run" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# PowerShell: the same properties, from the twin script
# ---------------------------------------------------------------------------
PS = shutil.which("powershell.exe") or shutil.which("pwsh")


def _ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True)


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_deploy_ps1_resolves_secrets_file_the_same_way(tmp_path):
    """-Secrets must replace the default the same way deploy.sh's does, so an
    operator who reads the bash runbook gets the same file from PowerShell."""
    text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    m = re.search(
        r"\$SecretsFile = if \(\$Secrets\) \{ \$Secrets \} else \{ Join-Path \$RepoRoot '([^']+)' \}",
        text,
    )
    assert m, "deploy.ps1 no longer resolves $SecretsFile from -Secrets in the expected form"
    assert m.group(1) == "secrets\\.env.local", m.group(1)


def _ps1_missing_file_block() -> str:
    """Both shipped missing-file `if` statements, cut verbatim out of
    deploy.ps1 as ONE contiguous block — not retyped, for the same reason
    test_force_step_list.py gives: a re-implementation can pass while the
    shipped code is broken. String-indexed rather than regexed: the second
    `if` nests its own `if ($DryRun) { } else { }`, so a naive "first closing
    brace" search would stop inside it."""
    text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    start_marker = "if ($Secrets -and -not (Test-Path $SecretsFile)) {\n"
    start = text.index(start_marker)
    end_marker = (
        'Rather than do a worse job of it here, use the bash one — it is a one-off.)\n'
        '"@\n'
        '    }\n'
        '}\n'
    )
    end = text.index(end_marker, start) + len(end_marker)
    fragment = text[start:end]
    assert "secrets-init.sh" in fragment
    assert "$DryRun" in fragment
    return fragment


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_deploy_ps1_dies_on_an_explicit_missing_file_without_secrets_init(tmp_path):
    """Same refusal as deploy.sh, in the shipped block an operator on Windows
    actually runs: a named, missing file must not fall through to any
    generation path (there is none in deploy.ps1 — see its own docstring
    on why -Secrets must still not blur into "no file at all")."""
    named = str(tmp_path / "does-not-exist.env")
    script = "\n".join([
        "function Die { param($m) Write-Host \"ERR $m\"; exit 7 }",
        "function Write-Warn { param($m) Write-Host \"WARN $m\" }",
        f"$Secrets = '{named}'",
        "$SecretsFile = $Secrets",
        "$DryRun = $false",
        _ps1_missing_file_block(),
        "Write-Host 'REACHED_END'",
    ])
    proc = _ps(script)
    assert proc.returncode == 7, (proc.returncode, proc.stdout, proc.stderr)
    assert "REACHED_END" not in proc.stdout
    assert "-Secrets" in proc.stdout
    assert "secrets-init" not in proc.stdout.lower()


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_deploy_ps1_dies_on_named_missing_file_even_on_dry_run(tmp_path):
    """Twin of the bash dry-run test: -DryRun must not rehearse past a
    misspelled -Secrets path either."""
    named = str(tmp_path / "does-not-exist.env")
    script = "\n".join([
        "function Die { param($m) Write-Host \"ERR $m\"; exit 7 }",
        "function Write-Warn { param($m) Write-Host \"WARN $m\" }",
        f"$Secrets = '{named}'",
        "$SecretsFile = $Secrets",
        "$DryRun = $true",
        _ps1_missing_file_block(),
        "Write-Host 'REACHED_END'",
    ])
    proc = _ps(script)
    assert proc.returncode == 7, (proc.returncode, proc.stdout, proc.stderr)
    assert "REACHED_END" not in proc.stdout
    assert "-Secrets" in proc.stdout


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_deploy_ps1_omitted_and_missing_still_names_the_bash_script(tmp_path):
    """$Secrets unset (today's behaviour) must keep telling the operator to run
    scripts/secrets-init.sh on a real run, not silently swallow the missing-file
    case."""
    missing = str(tmp_path / "secrets" / ".env.local")
    script = "\n".join([
        "function Die { param($m) Write-Host \"ERR $m\"; exit 7 }",
        "function Write-Warn { param($m) Write-Host \"WARN $m\" }",
        "$Secrets = $null",
        f"$SecretsFile = '{missing}'",
        "$DryRun = $false",
        _ps1_missing_file_block(),
        "Write-Host 'REACHED_END'",
    ])
    proc = _ps(script)
    assert proc.returncode == 7
    assert "REACHED_END" not in proc.stdout
    assert "secrets-init.sh" in proc.stdout


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_deploy_ps1_omitted_and_missing_tolerated_on_dry_run(tmp_path):
    """Twin of the bash dry-run tolerance test: a first install with no
    -Secrets given must still be able to rehearse via -DryRun."""
    missing = str(tmp_path / "secrets" / ".env.local")
    script = "\n".join([
        "function Die { param($m) Write-Host \"ERR $m\"; exit 7 }",
        "function Write-Warn { param($m) Write-Host \"WARN $m\" }",
        "$Secrets = $null",
        f"$SecretsFile = '{missing}'",
        "$DryRun = $true",
        _ps1_missing_file_block(),
        "Write-Host 'REACHED_END'",
    ])
    proc = _ps(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "REACHED_END" in proc.stdout
    assert "dry run" in proc.stdout.lower()


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_deploy_ps1_present_file_is_untouched(tmp_path):
    """The block must be a no-op once the file exists, named or not."""
    present = tmp_path / "present.env"
    present.write_text("SENTINEL_DB_PASSWORD=x\n", encoding="utf-8")
    script = "\n".join([
        "function Die { param($m) Write-Host \"ERR $m\"; exit 7 }",
        "function Write-Warn { param($m) Write-Host \"WARN $m\" }",
        f"$Secrets = '{present}'",
        f"$SecretsFile = '{present}'",
        "$DryRun = $false",
        _ps1_missing_file_block(),
        "Write-Host 'REACHED_END'",
    ])
    proc = _ps(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "REACHED_END" in proc.stdout
