"""A dry run must never block on a prompt — it is the rehearsal an operator
runs unattended, or pastes into a script, precisely because it changes
nothing on the server. Round-4 gap: `if (( ! DRY_RUN )) && (( ! ASSUME_YES ))`
guards the "some keys are missing, continue anyway?" prompt in deploy.sh, and
removing the `(( ! DRY_RUN ))` half of that condition changed nothing that any
test up to this point could see — the existing missing-key coverage
(test_deploy_secrets_flag.py) only checks WHICH secrets file gets used, never
what happens once a present-but-incomplete file is read on a real run versus a
--dry-run.

Without the guard, `--dry-run` with an incomplete secrets file would read
`read -r -p` from stdin like a real run. Fed empty input (a script with no
terminal attached, or a CI job), `read` returns an empty answer, which is not
"da", so the run dies — a rehearsal that is supposed to be side-effect-free
refusing to complete because of a prompt it should never have asked.

This test runs the SHIPPED fragment — the `if (( ${#missing[@]} > 0 )); then
... fi` block, cut verbatim out of deploy.sh — under DRY_RUN=1 with an empty
stdin, and checks it reaches the end without invoking `read` at all.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
BASH = shutil.which("bash")

pytestmark = [pytest.mark.security, pytest.mark.skipif(BASH is None, reason="no bash on PATH")]


def _env(**extra: str) -> dict[str, str]:
    return {**os.environ, "NO_COLOR": "1", **extra}


def _missing_keys_fragment() -> str:
    """The `if (( ${#missing[@]} > 0 )); then ... fi` block that decides
    whether to prompt about missing keys, cut verbatim, string-indexed rather
    than regexed for the same reason test_deploy_secrets_flag.py's
    _secrets_missing_fragment gives: a nested `if ($DryRun) ... fi` inside it
    would derail a naive "first closing fi" regex."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start_marker = "    missing=()\n"
    start = text.index(start_marker)
    end_marker = "    fi\n\n"
    end = text.index(end_marker, start) + len(end_marker)
    fragment = text[start:end]
    # Sanity-checks the EXTRACTION, not the property under test: "DRY_RUN" is
    # deliberately not asserted here, since the mutation this file exists to
    # catch removes exactly that token from this block, and a marker chosen
    # from the mutated line itself would trip on the mutation instead of on
    # the runtime behaviour the tests below actually check.
    assert "Continui oricum" in fragment
    assert "read -r -p" in fragment
    return fragment


HARNESS = """
set -u
warn() {{ printf 'WARN %s\\n' "$*" >&2; }}
die()  {{ printf 'ERR %s\\n' "$*" >&2; exit 1; }}

SECRETS_FILE="{secrets_file}"
DRY_RUN={dry_run}
ASSUME_YES={assume_yes}

{fragment}
printf 'REACHED_END\\n'
"""


def _run(tmp_path: Path, *, dry_run: int, assume_yes: int = 0,
         stdin: str = "") -> subprocess.CompletedProcess:
    fragment = _missing_keys_fragment()
    secrets_file = tmp_path / "secrets.env"
    # All four keys absent, so `missing` is never empty — the branch this
    # test is about always fires.
    secrets_file.write_text("SOME_OTHER_KEY=x\n", encoding="utf-8", newline="\n")
    script = HARNESS.format(
        secrets_file=secrets_file.as_posix(),
        dry_run=dry_run,
        assume_yes=assume_yes,
        fragment=fragment,
    )
    script_path = tmp_path / "harness.sh"
    script_path.write_text(script, encoding="utf-8", newline="\n")
    proc = subprocess.run([BASH, script_path.as_posix()], capture_output=True,
                          input=stdin.encode("utf-8"), env=_env())
    proc.stdout = proc.stdout.decode("utf-8", "replace")
    proc.stderr = proc.stderr.decode("utf-8", "replace")
    return proc


def out(proc: subprocess.CompletedProcess) -> str:
    return proc.stdout + proc.stderr


def test_dry_run_never_prompts_even_with_nothing_on_stdin(tmp_path):
    """The property this file exists to close: --dry-run with an incomplete
    secrets file must reach the end WITHOUT reading from stdin. Fed nothing on
    stdin (exactly what an unattended rehearsal has), the mutated version
    (guard removed) calls `read -r -p`, gets an empty answer, and dies —
    turning a side-effect-free rehearsal into a failure that has nothing to
    do with the secrets file itself."""
    proc = _run(tmp_path, dry_run=1, assume_yes=0, stdin="")
    assert proc.returncode == 0, out(proc)
    assert "REACHED_END" in proc.stdout, out(proc)
    assert "missing or empty" in out(proc)


def test_a_real_run_still_prompts_and_a_decline_stops_it(tmp_path):
    """The other half of the same property, so a fix that skips the prompt
    UNCONDITIONALLY (not just on --dry-run) would also be caught: a real run
    with missing keys and neither --yes nor an operator's "da" must still
    stop, exactly as before this change."""
    proc = _run(tmp_path, dry_run=0, assume_yes=0, stdin="NU\n")
    assert proc.returncode != 0
    assert "REACHED_END" not in proc.stdout
    assert "aborted" in out(proc)


def test_assume_yes_still_skips_the_prompt_on_a_real_run(tmp_path):
    """--yes must still answer this prompt on a REAL run — this property is
    unrelated to --dry-run and must survive untouched."""
    proc = _run(tmp_path, dry_run=0, assume_yes=1, stdin="")
    assert proc.returncode == 0, out(proc)
    assert "REACHED_END" in proc.stdout, out(proc)
