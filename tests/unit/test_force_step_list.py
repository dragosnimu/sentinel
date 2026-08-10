"""`--force-step` has to be able to re-run a set of steps, not one step.

The operator was told to put a new SENTINEL_DB_PASSWORD in secrets/.env.local
and re-deploy with `--from-step 22`. The run printed

    [=] step 22_postgres    (already done)
    [=] step 27_secrets     (already done)

in the middle of a hundred lines and ended with "installation finished". The
password had not been rotated: `--from-step N` only skips what is BELOW N, so a
marked step at or above N stays skipped.

`--force-step 22` alone would have been worse than useless. Rotating the
password is two steps that are one operation — 22 runs `ALTER ROLE sentinel
PASSWORD`, 27 rewrites /etc/sentinel/secrets.env — and `start_services` is in
ALWAYS_STEPS, so the daemons are restarted at the end of the same pass. Force
one and not the other, in either order, and the services come back
authenticating with one value against a database that expects the other: the
health gate fails and the operator is left with Sentinel down.

So each test below names the state the host would be left in if the behaviour
it pins were lost.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
LIB = REPO / "deploy" / "lib"
INSTALL_SH = REPO / "deploy" / "install.sh"
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
DEPLOY_PS1 = REPO / "scripts" / "deploy.ps1"

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="no bash on PATH")


def _env(**extra: str) -> dict[str, str]:
    """The caller's environment plus the overrides.

    Not a minimal env: on Windows, CreateProcess resolves the executable using
    the PATH it is handed, and a hand-built one finds WSL's bash instead of Git
    Bash — which fails with a Windows service error that looks nothing like a
    test failure.
    """
    return {**os.environ, "NO_COLOR": "1", **extra}


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
# Everything here sources the shipped deploy/lib/common.sh and calls the shipped
# functions. An earlier test in this repository re-implemented the logic it was
# checking and passed while the real code was broken; running the file that goes
# to the server is the only version of this test that means anything.
#
# Sourced by relative name from its own directory: an absolute Windows path
# reaches MSYS bash as `C:/...`, which it reads as a relative path under a
# directory called `C:`.

STEPS_SCRIPT = """
source ./common.sh
mkdir -p "$STATE_MARKERS"
body() { printf '%s\\n' "RAN:$1" >> "$LOG"; }
specs="${STEPS:-22:postgres 23:venv 27:secrets}"
for spec in $specs; do
    : > "${STATE_MARKERS}/$(printf '%02d_%s' "${spec%%:*}" "${spec#*:}")"
done
parse_force_steps "${FORCE_STEP:-}"
for spec in $specs; do
    run_step "${spec%%:*}" "${spec#*:}" body "${spec#*:}"
done
report_marked_skips
assert_forced_steps_ran
"""


def run_steps(tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess, list[str]]:
    """Run three marked steps through the real run_step, return (proc, bodies-run)."""
    state = str(tmp_path / "state").replace("\\", "/")
    log = str(tmp_path / "ran.log").replace("\\", "/")
    proc = subprocess.run(
        [BASH, "-c", STEPS_SCRIPT],
        cwd=LIB,
        capture_output=True,
        text=True,
        env=_env(SENTINEL_STATE_DIR=state, LOG=log, **env),
    )
    ran = Path(log).read_text(encoding="utf-8").split() if Path(log).exists() else []
    return proc, [line.split(":", 1)[1] for line in ran]


def bash_func(source: Path, name: str, call: str) -> subprocess.CompletedProcess:
    """Run one function lifted verbatim out of a shipped script.

    Used for scripts/deploy.sh, which cannot be sourced (it deploys). The body
    is cut from the file, not retyped, so it is still the shipped code that runs.
    """
    text = source.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\(\) \{{.*?^\}}", text, re.S | re.M)
    assert match, f"{name}() not found in {source.name}"
    script = (
        "die() { printf 'error: %s\\n' \"$*\" >&2; exit 1; }\n"
        + match.group(0)
        + "\n"
        + call
    )
    return subprocess.run(
        [BASH, "-c", script], capture_output=True, text=True, env=_env()
    )


# ---------------------------------------------------------------------------
# The rotation itself
# ---------------------------------------------------------------------------
def test_a_list_reruns_every_step_in_it_in_one_pass(tmp_path):
    """Without this, rotating the DB password cannot be done at all.

    Both halves have to happen before start_services restarts the daemons at the
    end of the run. Two separate runs cannot do it: the run that changes only one
    of the two ends with the services restarted against a mismatch, i.e. Sentinel
    down and unable to reach its own database.
    """
    proc, ran = run_steps(tmp_path, FORCE_STEP="22,27")
    assert proc.returncode == 0, proc.stderr
    assert ran == ["postgres", "secrets"]


def test_a_single_number_still_works(tmp_path):
    """The old form is what every runbook, the troubleshooting table and the
    self-check's suggested action still print. Breaking it would turn documented
    advice into an error message."""
    proc, ran = run_steps(tmp_path, FORCE_STEP="22")
    assert proc.returncode == 0, proc.stderr
    assert ran == ["postgres"]


def test_spaces_and_order_do_not_matter(tmp_path):
    """`--force-step 27, 22` is what a hurried operator types at 3 a.m. Silently
    doing nothing with it is the failure mode this whole change exists to end."""
    proc, ran = run_steps(tmp_path, FORCE_STEP=" 27 , 22 ")
    assert proc.returncode == 0, proc.stderr
    assert ran == ["postgres", "secrets"]


def test_a_leading_zero_is_read_as_decimal(tmp_path):
    """`08` and `09` are invalid octal. Left to bash arithmetic they abort the
    installer with a syntax error halfway through argument handling instead of
    running the step."""
    proc, ran = run_steps(tmp_path, FORCE_STEP="022")
    assert proc.returncode == 0, proc.stderr
    assert ran == ["postgres"]


# ---------------------------------------------------------------------------
# Refusals — a half-obeyed list is the dangerous outcome
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    ["22,twenty-seven", "22,", ",27", "22,,27", "-22", "22.5", "22;27", "abc", " "],
    ids=["word-in-list", "trailing-comma", "leading-comma", "empty-element",
         "negative", "not-an-integer", "semicolon", "no-digits", "blank"],
)
def test_a_bad_value_refuses_the_whole_list(tmp_path, value):
    """A run that forces half of `22,twenty-seven` changes the password in the
    database and leaves secrets.env holding the old one — which is exactly the
    state that takes Sentinel down. Refusing before any step runs leaves the host
    untouched instead."""
    proc, ran = run_steps(tmp_path, FORCE_STEP=value)
    assert proc.returncode != 0, f"{value!r} was accepted; stdout={proc.stdout}"
    assert ran == [], f"{value!r} ran steps before being refused: {ran}"
    assert "--force-step" in proc.stderr


def test_a_space_separated_list_is_refused_not_concatenated(tmp_path):
    """`--force-step "22 27"` must be an error, never step 2227.

    Stripping whitespace before checking the shape would turn it into a single
    number that matches nothing — the request would be accepted and obeyed as
    something else. The run would still end badly, but for the wrong reason and
    much later, blaming a step number the operator never typed.

    So the refusal has to happen in the parser, and the number 2227 must never
    be invented at all: it must appear in no message, in either stream.
    """
    proc, ran = run_steps(tmp_path, FORCE_STEP="22 27")
    assert proc.returncode != 0
    assert ran == []
    assert "is not a step number" in proc.stderr, proc.stderr
    assert "2227" not in proc.stdout + proc.stderr


def test_an_unparsed_force_step_cannot_be_ignored(tmp_path):
    """If a future caller sets FORCE_STEP and forgets to parse it, the installer
    must stop, not run as though the flag had never been passed.

    Silently discarding the flag is the original bug wearing different clothes:
    the operator asks for a rotation, the run reports success, nothing rotates.
    """
    script = STEPS_SCRIPT.replace('parse_force_steps "${FORCE_STEP:-}"', ":")
    state = str(tmp_path / "state").replace("\\", "/")
    proc = subprocess.run(
        [BASH, "-c", script], cwd=LIB, capture_output=True, text=True,
        env=_env(SENTINEL_STATE_DIR=state, LOG=str(tmp_path / "x.log"),
                 FORCE_STEP="22,27"),
    )
    assert proc.returncode != 0
    assert "parse_force_steps" in proc.stderr


# ---------------------------------------------------------------------------
# Effect, not intent
# ---------------------------------------------------------------------------
def test_a_forced_step_that_never_ran_ends_the_run(tmp_path):
    """--from-step is applied before --force-step, so `--from-step 27
    --force-step 22` skips step 22 instead of forcing it.

    install.sh refuses that combination up front. This pins the check behind it:
    clearing a marker is intent, running the body is effect, and only the second
    one may be reported as success. Otherwise the run ends "finished" with the
    rotation half done.
    """
    proc, ran = run_steps(tmp_path, FORCE_STEP="22", FROM_STEP="27")
    assert proc.returncode != 0
    assert ran == []                   # 22 was skipped by --from-step, not forced
    assert "22" in proc.stderr


def test_the_success_line_names_the_steps_that_actually_ran(tmp_path):
    """The operator needs a fact to check, not a claim. The line names the step
    numbers whose bodies executed in this pass."""
    proc, _ = run_steps(tmp_path, FORCE_STEP="22,27")
    assert re.search(r"--force-step:.*\b22\b.*\b27\b", proc.stdout), proc.stdout


def test_from_step_says_out_loud_what_it_did_not_do(tmp_path):
    """The `(already done)` lines that hid the failed rotation.

    With --from-step in play, a marked step is a request being declined. It is
    printed as such, and summarised once at the end with the flag that would
    actually do it — so the next operator does not have to know that --from-step
    and --force-step differ.
    """
    proc, ran = run_steps(tmp_path, FROM_STEP="22")
    assert proc.returncode == 0, proc.stderr
    assert ran == []
    assert "--from-step does not re-run it" in proc.stdout
    combined = proc.stdout + proc.stderr
    assert "22_postgres" in combined and "27_secrets" in combined
    assert "--force-step 22,23,27" in combined


def test_the_suggested_command_omits_steps_this_file_calls_dangerous(tmp_path):
    """A generated command reads as advice, and gets pasted.

    Step 29 re-loads the nftables table. `ALWAYS_STEPS` keeps it out for exactly
    that reason — re-creating the table can empty the named sets, i.e. silently
    unblock everything currently blocked. Offering `--force-step …,29` in a
    ready-to-paste line would have been the installer telling the operator to do
    it, in the same breath as a warning.
    """
    proc, _ = run_steps(tmp_path, FROM_STEP="22", STEPS="22:postgres 29:nftables")
    combined = proc.stdout + proc.stderr
    suggestion = [l for l in combined.splitlines() if "--force-step " in l]
    assert suggestion, combined
    assert not any("29" in l for l in suggestion), \
        f"29 is offered for pasting: {suggestion}"
    # Omitted, but not hidden: the operator is told it exists and why it is out.
    assert "29_nftables" in combined
    assert "nftables" in combined and "blocat" in combined


# ---------------------------------------------------------------------------
# The numbers have to be steps of this installer
# ---------------------------------------------------------------------------
def _exists_check(force_steps: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [BASH, "-c",
         f"source ./common.sh; FORCE_STEPS=({force_steps}); "
         f"assert_force_steps_exist ../install.sh && echo ACCEPTED"],
        cwd=LIB, capture_output=True, text=True, env=_env(),
    )


def test_real_step_numbers_are_accepted():
    """22 and 27 are the two the rotation procedure documents. If a renumbering
    ever moves them, this fails here rather than on the server."""
    proc = _exists_check("22 27")
    assert proc.returncode == 0 and "ACCEPTED" in proc.stdout, proc.stderr


def test_a_number_that_is_not_a_step_is_refused():
    """`--force-step 22,72` — a typo for 27 — would clear one marker, run one
    step and finish green: password changed in PostgreSQL, secrets.env stale,
    services restarted into the mismatch."""
    proc = _exists_check("22 72")
    assert proc.returncode != 0
    assert "72" in proc.stderr and "ACCEPTED" not in proc.stdout


def test_unreadable_and_wrong_are_reported_as_different_things():
    """"I cannot read the step list" is not "that step does not exist".

    If the extraction ever stops matching install.sh's `run_step` lines, every
    number becomes "unknown" and the operator is told their perfectly good
    `--force-step 22` is not a step — sending them to fix an argument that was
    never the problem. The refusal is right either way; the message has to say
    which of the two it is.
    """
    proc = subprocess.run(
        [BASH, "-c",
         "source ./common.sh; FORCE_STEPS=(22); "
         "assert_force_steps_exist ./common.sh && echo ACCEPTED"],
        cwd=LIB, capture_output=True, text=True, env=_env(),
    )
    assert proc.returncode != 0, "a file with no run_step lines accepted a step"
    assert "ACCEPTED" not in proc.stdout
    assert "no run_step lines" in proc.stderr, proc.stderr


def test_a_force_step_below_from_step_is_refused_at_startup():
    """`--from-step 27 --force-step 22` cannot do what it looks like it does.

    run_step applies --from-step first, so step 22 is skipped and the force is
    discarded. The end-of-run check would catch it, but only after everything
    else had already run — including start_services. Refuse the combination
    before the first step instead.
    """
    ok = bash_func(INSTALL_SH, "assert_force_steps_above_from_step",
                   'FROM_STEP=22; FORCE_STEPS=(22 27); '
                   'assert_force_steps_above_from_step && echo ACCEPTED')
    assert "ACCEPTED" in ok.stdout, ok.stderr

    bad = bash_func(INSTALL_SH, "assert_force_steps_above_from_step",
                    'FROM_STEP=27; FORCE_STEPS=(22); '
                    'assert_force_steps_above_from_step && echo ACCEPTED')
    assert "ACCEPTED" not in bad.stdout
    assert "22" in bad.stderr and "27" in bad.stderr


# ---------------------------------------------------------------------------
# The wiring. Every function above worked and none of it was connected to
# anything — five separate deletions in install.sh left this file green.
# ---------------------------------------------------------------------------
def _main_body() -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    return text.split("\nmain() {", 1)[1].split("\n}\n", 1)[0]


def _top_level_before_main() -> str:
    """Statements that run at load time, before main() is even defined."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    head = text.split("\nmain() {", 1)[0]
    return "\n".join(l for l in head.splitlines() if l and not l[0].isspace())


def test_install_sh_checks_the_forced_steps_before_declaring_success():
    """The checks exist; being called is a separate fact.

    `assert_forced_steps_ran` is the only thing standing between "the operator
    asked for a rotation that did not happen" and "Instalare completă". Called
    after the banner it is worthless — the operator has already read the line
    that says it worked and stopped watching.
    """
    body = _main_body()
    for name in ("report_marked_skips", "assert_forced_steps_ran"):
        assert re.search(rf"^\s*{name}\s*$", body, re.M), f"main() never calls {name}"
    banner = body.index('section "Instalare completă"')
    assert body.index("assert_forced_steps_ran") < banner, \
        "the effect check runs after the success banner"
    assert body.index("report_marked_skips") < banner


def test_install_sh_resolves_step_selection_before_the_first_step():
    """All three refusals have to happen at load time, not inside main().

    Anywhere later and the installer has already changed something before
    deciding the arguments were nonsense — which for a rotation means the
    database password changed and secrets.env did not.
    """
    head = _top_level_before_main()
    assert re.search(r'^parse_force_steps "\$FORCE_STEP"', head, re.M)
    assert re.search(r'^assert_force_steps_exist ', head, re.M)
    assert re.search(r'^assert_force_steps_above_from_step$', head, re.M)
    # And --from-step must be a number, or the comparison in the check above
    # silently evaluates garbage as 0 and lets everything through.
    assert re.search(r'FROM_STEP.*=~ \^\[0-9\]\+\$', head), \
        "--from-step is not validated as a number"


def test_help_still_prints_the_flags_it_documents():
    """--help prints a fixed line range of the header. Add a paragraph above it
    and the range silently starts cutting off the bottom — which is how an
    operator ends up reading half a flag description and guessing the rest."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(r"--help\|-h\)\s*sed -n '(\d+),(\d+)p'", text)
    assert match, "the --help handler is no longer a sed range over the header"
    first, last = int(match.group(1)), int(match.group(2))
    shown = "\n".join(text.splitlines()[first - 1:last])
    assert "--force-step N[,N…]" in shown
    assert "comma-separated list" in shown
    assert "--from-step N" in shown
    # And it must not stop in the middle of a sentence, as it did before.
    assert shown.rstrip().endswith(".")


# ---------------------------------------------------------------------------
# The wrappers: both are shipped, both must behave the same
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [("22", "22"), ("22,27", "22,27"), ("22, 27", "22,27"), (" 27 ,22 ", "27,22")],
)
def test_deploy_sh_normalises_a_list_into_one_argument(value, expected):
    """The value is interpolated into the remote command line unquoted. A space
    left in it splits into two arguments and install.sh dies on the second —
    after the tarball has been shipped and sudo has been primed."""
    proc = bash_func(DEPLOY_SH, "normalize_step_list",
                     f'normalize_step_list "{value}" --force-step')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == expected


@pytest.mark.parametrize("value", ["22 27", "22,x", "22,", "", "twenty-two"])
def test_deploy_sh_refuses_what_install_sh_would_refuse(value):
    """Both ends check, and they have to agree. A wrapper that accepts more than
    the installer produces a failure on the server, halfway through a run."""
    proc = bash_func(DEPLOY_SH, "normalize_step_list",
                     f'normalize_step_list "{value}" --force-step')
    assert proc.returncode != 0, f"{value!r} accepted, output {proc.stdout!r}"


def test_deploy_sh_actually_forwards_the_flag():
    """Normalising it and then not passing it on would be a silent no-op — the
    shape of bug that put this file here."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert re.search(r"INSTALL_ARGS\+=\(--force-step \"\$FORCE_STEP\"\)", text)


# --- PowerShell ------------------------------------------------------------
PS = shutil.which("powershell.exe") or shutil.which("pwsh")


def _ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True)


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_powershell_turns_a_bare_comma_into_an_array():
    """The measurement behind the [string[]] declaration, not an assumption.

    In argument mode a comma is an array constructor. Bound to a [string]
    parameter the array is coerced with $OFS and `22,27` arrives as `22 27` —
    two arguments on the remote command line, and the installer dies on the
    second one. If PowerShell's binding ever changed, the reason for the
    declaration below would need re-reading, so it is pinned here.
    """
    proc = _ps(
        "$s = { param([string]$V) $V }; "
        "$a = { param([string[]]$V) $V -join ',' }; "
        "Write-Output ('str=' + (& $s -V 22,27)); "
        "Write-Output ('arr=' + (& $a -V 22,27))"
    )
    assert "str=22 27" in proc.stdout, proc.stdout
    assert "arr=22,27" in proc.stdout, proc.stdout


def test_deploy_ps1_declares_the_parameter_as_a_string_array():
    """[string]$ForceStep would silently mangle `-ForceStep 22,27` into `22 27`
    — see the test above. This is the fix for that, and it is one word."""
    text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    assert re.search(r"\[string\[\]\]\$ForceStep", text)
    assert "--force-step $forceStepList" in text


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
@pytest.mark.parametrize(
    "call,expected",
    [("-Value 22 -Flag '-ForceStep'", "22"),
     ("-Value 22,27 -Flag '-ForceStep'", "22,27"),
     ("-Value '22,27' -Flag '-ForceStep'", "22,27"),
     ("-Value '22, 27' -Flag '-ForceStep'", "22,27"),
     ("-Value 22, 27 -Flag '-ForceStep'", "22,27")],
)
def test_deploy_ps1_normalises_every_form_the_operator_might_type(call, expected):
    """deploy.sh and deploy.ps1 are both shipped and must behave identically.
    An operator who reads the bash runbook and works from PowerShell has to get
    the same rotation, not a different one."""
    body = _powershell_function(DEPLOY_PS1.read_text(encoding="utf-8-sig"), "Get-StepList")
    proc = _ps("function Die { param($m) Write-Error $m; exit 3 }\n"
               f"function Get-StepList {{{body}}}\n"
               f"Write-Output ('OUT=' + (Get-StepList {call}))")
    assert proc.returncode == 0, proc.stderr
    assert f"OUT={expected}" in proc.stdout, proc.stdout


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
@pytest.mark.parametrize("call", ["-Value '22 27'", "-Value '22,x'", "-Value '22,'"])
def test_deploy_ps1_refuses_what_deploy_sh_refuses(call):
    """Same inputs, same refusal. A list that one wrapper accepts and the other
    mangles is worse than a flag neither supports."""
    body = _powershell_function(DEPLOY_PS1.read_text(encoding="utf-8-sig"), "Get-StepList")
    proc = _ps("function Die { param($m) Write-Error $m; exit 3 }\n"
               f"function Get-StepList {{{body}}}\n"
               f"Write-Output ('OUT=' + (Get-StepList {call} -Flag '-ForceStep'))")
    assert "OUT=" not in proc.stdout, proc.stdout


def _powershell_function(text: str, name: str) -> str:
    """(body) of `function X { ... }`, by brace depth. Crude, but it only has to
    handle the two scripts in this repo and no PowerShell parser is available to
    pytest."""
    match = re.search(rf"^function\s+{re.escape(name)}\s*\{{", text, re.M)
    assert match, f"{name} not found"
    depth, i = 0, match.end() - 1
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return text[match.end():i]


# ---------------------------------------------------------------------------
# The documented procedure has to match the installer
# ---------------------------------------------------------------------------
def _step_number(name: str) -> str:
    match = re.search(rf"^\s*run_step\s+(\d+)\s+{name}\b", INSTALL_SH.read_text(encoding="utf-8"), re.M)
    assert match, f"no run_step line for {name}"
    return match.group(1)


def test_the_rotation_procedure_names_the_installer_s_actual_steps():
    """A runbook with the wrong step numbers is worse than none: it is followed.

    If the steps are ever renumbered, the procedure in OPERARE.md §11 stops
    matching the installer and this fails — instead of an operator forcing two
    steps that no longer do what the document says they do.
    """
    operare = (REPO / "docs" / "OPERARE.md").read_text(encoding="utf-8")
    expected = f"--force-step {_step_number('postgres')},{_step_number('secrets')}"
    assert expected in operare, f"OPERARE.md does not document `{expected}`"


def test_the_rotation_proof_only_asks_for_what_the_public_panel_renders():
    """A verification step the operator cannot perform is not a verification.

    §11 (d) told them to read `seq` on the witness's page. That row is behind
    `detailed`, which needs `?key=<SENTINEL_CHECK_SECRET>` — so following the
    procedure ends at a number that is not on screen, during the one moment the
    operator is trying to confirm the beacon survived.
    """
    operare = (REPO / "docs" / "OPERARE.md").read_text(encoding="utf-8")
    page = (REPO / "watcher" / "app" / "page.tsx").read_text(encoding="utf-8")

    # What the page renders without a key: everything before the `detailed` gate.
    public = page.split("{detailed &&", 1)[0]
    assert "Ultimul semnal" in public, "the public panel no longer shows the age"

    section = operare.split("## 11.", 1)[1]
    if "seq" in section or "Semnal nr." in section:
        assert "SENTINEL_CHECK_SECRET" in section, \
            "§11 asks for a detail-only field without saying it needs the key"


def test_the_reason_the_two_steps_are_inseparable_still_holds():
    """The procedure says the daemons are restarted in the same pass, which is
    why 22 and 27 cannot be split across two runs. That is only true while
    start_services is an ALWAYS step; if it stopped being one, the document
    would be reasoning from something that is no longer the case."""
    common = (LIB / "common.sh").read_text(encoding="utf-8")
    always = re.search(r"ALWAYS_STEPS=\"(.*?)\"", common, re.S).group(1).split()
    assert "start_services" in always
