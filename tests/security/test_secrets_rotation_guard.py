"""A deploy that overwrites the wrong host's secrets must say so before it happens.

Measured on 2026-09-05: the active secrets/.env.local was a mixture of one
host's Telegram bot token and another host's database password — installing
it would have run a second Sentinel carrying the first one's bot token, and
the two cancelled each other out on Telegram's getUpdates (32 Conflict errors
in 30 minutes on production). Separately, the per-host copy kept as a
fallback was three weeks stale and differed from the live host on six keys,
SENTINEL_BEACON_SECRET among them, and a rotated beacon secret makes the
external watcher reject every signal as a bad one, which looks exactly like
the host having gone silent.

`compare_secrets_with_host` is the guard that would have named every one of
those keys before either file reached the wire. A first round of this guard
shipped three defects a code-verifier found and this file now covers:

  * `--dry-run` used to skip the whole comparison — the recorded production
    invocation always carries [--dry-run], so the incident this guard exists
    to close was never rehearsed for the command the operator actually types.
    Fixed: the comparison runs on a dry run too, report-only, never gating.
  * `--yes` used to be sufficient, alone, to wave a rotation through — the
    exact shape of the original incident (a stale fallback answering every
    prompt). Fixed: rotation consent is `--allow-rotation` /
    `--allow-rotation-keys`, and `--yes` no longer implies it.
  * `remote_out="$(ssh_run ... 2>&1)"` merged ssh's OWN stderr (a PQ-key-
    exchange warning this OpenSSH build prints on every connection) into the
    text parsed as KEY HASH lines, and the same assignment shape meant a
    failing `sudo -n` under `set -euo pipefail` killed the script before its
    own `remote_rc=$?` could be read — no message at all. Fixed: the ssh
    client's stderr goes to a separate file, and the assignment is the
    CONDITION of an `if`, exempt from `-e`.

These tests run the SHIPPED function — `REMOTE_SECRETS_SCRIPT`,
`REMOTE_SECRETS_SCRIPT_B64`, `rotation_allowed` and `compare_secrets_with_host`,
cut verbatim out of scripts/deploy.sh — against a fabricated local file and a
fabricated "host" file, under the SAME `set -euo pipefail` the real script
runs under. `ssh_run` is stubbed, but the stub DECODES AND EXECUTES the real
base64-encoded script this function builds, and always adds a line of noise
to its own stderr the way a real ssh client would; only the transport (an
actual SSH connection to a real host) and whether `sudo -n` succeeds are
faked. A stub that fabricated the comparison result instead would prove
nothing about the code that ships, and a harness that relaxed `set -e` would
prove nothing about the bug it was written to catch.
"""

from __future__ import annotations

import hashlib
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

pytestmark = [pytest.mark.security, pytest.mark.skipif(BASH is None, reason="no bash on PATH")]


def _env(**extra: str) -> dict[str, str]:
    return {**os.environ, "NO_COLOR": "1", **extra}


def _fragment() -> str:
    """REMOTE_SECRETS_SCRIPT, REMOTE_SECRETS_SCRIPT_B64, rotation_allowed and
    compare_secrets_with_host, cut verbatim as one contiguous block.

    Matched by BRACE DEPTH on `compare_secrets_with_host() {`, not by "the
    first bare `}` at column 0": rotation_allowed() is now a second top-level
    function between the two markers, with its own closing brace at column 0,
    and a non-greedy scan for that shape would stop there and silently test
    half the shipped code — exactly the class of bug this docstring's own
    previous version warned about and then walked into. `${...}` parameter
    expansions inside the body are self-balanced (one `{` and one `}` each),
    so plain character-level depth counting still lands on the right brace;
    this is the same technique tests/unit/test_force_step_list.py uses for
    the PowerShell twin (_powershell_function, copied into this file below)."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start_m = re.search(r"^REMOTE_SECRETS_SCRIPT=\"\$\(cat <<'REMOTE_SCRIPT'\n", text, re.M)
    assert start_m, "REMOTE_SECRETS_SCRIPT heredoc start not found"
    func_m = re.search(r"^compare_secrets_with_host\(\) \{", text, re.M)
    assert func_m, "compare_secrets_with_host() not found"
    depth = 0
    i = func_m.end() - 1  # position of the function's opening '{'
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    assert depth == 0, "compare_secrets_with_host() never closes — brace count did not return to 0"
    body = text[start_m.start():i + 1]
    assert "rotation_allowed()" in body
    assert "compare_secrets_with_host()" in body
    return body


HARNESS = r"""
set -euo pipefail
info() { printf 'INFO %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*" >&2; }
ok()   { printf 'OK %s\n' "$*"; }
die()  { printf 'ERR %s\n' "$*" >&2; exit 1; }

HOST="host.invalid"
SECRETS_FILE="{secrets_file}"
ASSUME_YES={assume_yes}
DRY_RUN={dry_run}
ALLOW_ROTATION_ALL={allow_rotation_all}
ALLOW_ROTATION_KEYS="{allow_rotation_keys}"

# Stub transport. Decodes the REAL base64 blob compare_secrets_with_host
# built and runs it, repointing only the target path at the fixture that
# stands in for /etc/sentinel/secrets.env — the decode-and-hash pipeline
# itself is the shipped code, unmodified. Always writes a line of noise to
# ITS OWN stderr first, the way this OpenSSH build's PQ-key-exchange warning
# does on every real connection — proving that noise never reaches
# $remote_out is exactly what test_noisy_ssh_stderr_is_not_parsed_as_a_key
# below checks.
SUDO_OK={sudo_ok}
HOST_FIXTURE="{host_fixture}"
ssh_run() {
    printf '** WARNING: connection is not using a post-quantum key exchange **\n' >&2
    if [[ "$SUDO_OK" != 1 ]]; then
        printf 'sudo: a password is required\n' >&2
        return 1
    fi
    local cmd="$1" b64 script
    b64="$(printf '%s' "$cmd" | sed -n "s/.*printf '%s' '\([^']*\)'.*/\1/p")"
    script="$(printf '%s' "$b64" | base64 -d)"
    script="${script//\/etc\/sentinel\/secrets.env/$HOST_FIXTURE}"
    bash -c "$script"
}

{fragment}

compare_secrets_with_host
printf 'RC=%s\n' "$?"
"""


def run(tmp_path: Path, local_content: str, host_content: str | None, *,
       sudo_ok: bool = True, assume_yes: int = 0, dry_run: int = 0,
       allow_rotation_all: int = 0, allow_rotation_keys: str = "",
       stdin: str = "") -> subprocess.CompletedProcess:
    secrets_file = tmp_path / "local.env"
    secrets_file.write_text(local_content, encoding="utf-8", newline="\n")
    host_fixture = tmp_path / "host_secrets.env"
    if host_content is not None:
        host_fixture.write_text(host_content, encoding="utf-8", newline="\n")

    script = (
        HARNESS
        .replace("{secrets_file}", secrets_file.as_posix())
        .replace("{assume_yes}", str(assume_yes))
        .replace("{dry_run}", str(dry_run))
        .replace("{allow_rotation_all}", str(allow_rotation_all))
        .replace("{allow_rotation_keys}", allow_rotation_keys)
        .replace("{sudo_ok}", "1" if sudo_ok else "0")
        .replace("{host_fixture}", host_fixture.as_posix())
        .replace("{fragment}", _fragment())
    )
    script_path = tmp_path / "harness.sh"
    script_path.write_text(script, encoding="utf-8", newline="\n")
    # Bytes, not text=True, for the INPUT. On Windows, subprocess.run's
    # text-mode stdin performs universal-newline translation, rewriting the
    # "\n" this test asks for into "\r\n" before it ever reaches bash. `read
    # -r` strips the trailing \n but not a \r, so "da" arrives as "da\r" and
    # the confirmation prompt would compare unequal even when the operator
    # typed exactly the documented answer — a red that belongs to this
    # harness, not to compare_secrets_with_host. See
    # tests/security/test_secrets_preserved.py's run_reader for the same fix.
    proc = subprocess.run([BASH, script_path.as_posix()], capture_output=True,
                          input=stdin.encode("utf-8"), env=_env())
    proc.stdout = proc.stdout.decode("utf-8", "replace")
    proc.stderr = proc.stderr.decode("utf-8", "replace")
    return proc


def out(proc: subprocess.CompletedProcess) -> str:
    """info/ok go to stdout, warn/die go to stderr — the assertions below care
    that a message appears (or does not), not which stream it landed on."""
    return proc.stdout + proc.stderr


def _h(value: str) -> str:
    """The same hash compare_secrets_with_host computes, for building fixtures
    whose expected report is known ahead of time."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


HOST_SECRETS = {
    "ANTHROPIC_API_KEY": "value-of-the-anthropic-key",
    "TELEGRAM_BOT_TOKEN": "value-of-the-bot-token",
    "TELEGRAM_CHAT_ID": "123456789",
    "SENTINEL_DB_PASSWORD": "OLD-db-password",
    "SENTINEL_BEACON_SECRET": "c" * 64,
}


def _dump(values: dict[str, str]) -> str:
    return "".join(f"{k}={v}\n" for k, v in values.items())


# ---------------------------------------------------------------------------
# The failure this exists to close
# ---------------------------------------------------------------------------
def test_a_mixed_file_is_named_key_by_key(tmp_path):
    """The 2026-09-05 incident, reproduced: a local file carrying one host's
    bot token and a different db password than the live host. Both keys must
    be named as changing; a rotation that only caught one of them would still
    have shipped the other half of the mix-up silently."""
    local = dict(HOST_SECRETS,
                 TELEGRAM_BOT_TOKEN="value-from-the-OTHER-host",
                 SENTINEL_DB_PASSWORD="value-from-the-OTHER-host-too")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), stdin="da\n")
    assert "RC=0" in proc.stdout, out(proc)
    changed_line = next(l for l in out(proc).splitlines() if "would get a NEW value" in l)
    assert "TELEGRAM_BOT_TOKEN" in changed_line
    assert "SENTINEL_DB_PASSWORD" in changed_line
    assert "ANTHROPIC_API_KEY" not in changed_line, \
        f"an unchanged key was reported as changing: {changed_line}"


def test_the_beacon_secret_gets_its_own_sentence(tmp_path):
    """SENTINEL_BEACON_SECRET rotating alone is the silent failure: the beacon
    signs with the new value, the external watcher still has the old one, and
    every signal is rejected as a bad signature — indistinguishable from the
    host having gone dark. The warning must name that consequence, not just
    the key."""
    local = dict(HOST_SECRETS, SENTINEL_BEACON_SECRET="d" * 64)
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), stdin="da\n")
    assert "SENTINEL_BEACON_SECRET" in out(proc)
    assert "watcher" in out(proc) and "silent" in out(proc)


def test_a_value_never_appears_in_any_output(tmp_path):
    """The whole point: comparison by hash, never by value. If a real secret
    ever leaked into this function's output, an operator pasting a deploy log
    for help would be pasting the credential itself."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="brand-new-distinctive-value-9f2e")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), stdin="da\n")
    combined = proc.stdout + proc.stderr
    assert "brand-new-distinctive-value-9f2e" not in combined
    assert HOST_SECRETS["SENTINEL_DB_PASSWORD"] not in combined
    assert HOST_SECRETS["SENTINEL_BEACON_SECRET"] not in combined
    assert HOST_SECRETS["TELEGRAM_BOT_TOKEN"] not in combined


# ---------------------------------------------------------------------------
# The three groups
# ---------------------------------------------------------------------------
def test_an_identical_file_produces_no_warning(tmp_path):
    """The common case — a redeploy of the same host with nothing rotated —
    must not train the operator to expect (and click through) a warning on
    every single deploy. That is how a real one stops being read."""
    proc = run(tmp_path, _dump(HOST_SECRETS), _dump(HOST_SECRETS))
    assert "RC=0" in proc.stdout, out(proc)
    assert "would get a NEW value" not in out(proc)
    assert "no existing key would change" in out(proc)


def test_a_new_key_is_reported_as_local_only_not_changed(tmp_path):
    """Adding TELEGRAM_APPLY_PIN for the first time is not a rotation risk —
    there is no old value to lose — and must not trigger the confirmation
    gate that a real rotation does."""
    local = dict(HOST_SECRETS, TELEGRAM_APPLY_PIN="4242")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS))
    assert "RC=0" in proc.stdout, out(proc)
    assert "would get a NEW value" not in out(proc)
    assert "only in the local file" in out(proc) and "TELEGRAM_APPLY_PIN" in out(proc)


def test_a_host_only_key_is_reported_but_not_gated(tmp_path):
    """A key on the host that the local file does not mention (e.g. one set by
    hand, or belonging to another rotation channel) is untouched by this run —
    step 27 on the server carries it forward. Reported for visibility, not
    gated, because nothing here is about to change it."""
    host = dict(HOST_SECRETS, SENTINEL_SHIP_SECRET="e" * 64)
    proc = run(tmp_path, _dump(HOST_SECRETS), _dump(host))
    assert "RC=0" in proc.stdout, out(proc)
    assert "would get a NEW value" not in out(proc)
    assert "only on the host" in out(proc) and "SENTINEL_SHIP_SECRET" in out(proc)


# ---------------------------------------------------------------------------
# First install
# ---------------------------------------------------------------------------
def test_a_host_with_no_secrets_file_is_a_first_install_not_a_warning(tmp_path):
    """A host that has never had secrets.env must not be reported as though
    every key were being rotated away from something — there is nothing to
    rotate away from."""
    proc = run(tmp_path, _dump(HOST_SECRETS), None)
    assert "RC=0" in proc.stdout, out(proc)
    assert "first install" in out(proc)
    assert "would get a NEW value" not in out(proc)
    assert "only on the host" not in out(proc)
    assert "only in the local file" not in out(proc)


# ---------------------------------------------------------------------------
# The confirmation gate — interactive path (no --allow-rotation given)
# ---------------------------------------------------------------------------
def test_declining_the_prompt_sends_nothing(tmp_path):
    """"NU" at the rotation prompt must stop the deploy before anything is
    packaged or transferred — the whole point of asking first."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), stdin="NU\n")
    assert "RC=0" not in proc.stdout
    assert proc.returncode != 0


def test_accepting_the_prompt_proceeds(tmp_path):
    """"da" is the documented answer (docs/OPERARE.md), and a legitimate
    rotation must be able to proceed through it — with no --allow-rotation at
    all, because an interactive operator typing "da" IS the consent."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), stdin="da\n")
    assert "RC=0" in proc.stdout, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# --yes must NOT authorise a rotation by itself (round-2 fix)
# ---------------------------------------------------------------------------
def test_assume_yes_alone_refuses_a_rotation_rather_than_waving_it_through(tmp_path):
    """The exact shape of the 2026-09-05 incident: a stale fallback file with
    a rotated SENTINEL_BEACON_SECRET, deployed under --yes because that is
    what the recorded production invocation carries. --yes must no longer be
    sufficient by itself — the whole point of this test is that it is NOT the
    old test_assume_yes_proceeds..., which asserted the exact behaviour this
    round exists to remove."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), assume_yes=1, stdin="")
    assert "RC=0" not in proc.stdout, out(proc)
    assert proc.returncode != 0
    assert "SENTINEL_DB_PASSWORD" in out(proc)
    assert "--allow-rotation" in out(proc)


def test_assume_yes_with_allow_rotation_all_proceeds_and_still_names_the_key(tmp_path):
    """The legitimate scripted path (docs/OPERARE.md §11): --yes for the other
    prompts, --allow-rotation for this one. Must not go silent the way the
    incident did — the rotating key names still have to reach the log, the
    only record an unattended run leaves behind."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS),
              assume_yes=1, allow_rotation_all=1, stdin="")
    assert "RC=0" in proc.stdout, out(proc)
    assert "SENTINEL_DB_PASSWORD" in out(proc)
    assert "allowed by --allow-rotation" in out(proc)


def test_allow_rotation_keys_covers_only_the_named_key(tmp_path):
    """--allow-rotation-keys is per-key consent, not a blanket one: a key NOT
    on the list must still gate, even if another key changing at the same
    time was explicitly allowed."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password",
                 TELEGRAM_BOT_TOKEN="a-new-token")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS),
              assume_yes=1, allow_rotation_keys="SENTINEL_DB_PASSWORD", stdin="")
    assert "RC=0" not in proc.stdout, out(proc)
    assert proc.returncode != 0
    assert "TELEGRAM_BOT_TOKEN" in out(proc)
    assert "--allow-rotation" in out(proc)


def test_allow_rotation_keys_is_an_exact_match_not_a_prefix(tmp_path):
    """--allow-rotation-keys names KEYS, not prefixes of them. Round-4 gap:
    changing rotation_allowed's `[[ "$list_k" == "$k" ]]` to a prefix test
    (e.g. `[[ "$k" == "$list_k"* ]]`) stayed green under every test that
    existed before this one, because none of them ever allowed a key that was
    a strict PREFIX of the one actually changing. --allow-rotation-keys
    SENTINEL_DB must not silently also cover SENTINEL_DB_PASSWORD — that is a
    consent the operator never typed."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS),
              assume_yes=1, allow_rotation_keys="SENTINEL_DB", stdin="")
    assert "RC=0" not in proc.stdout, out(proc)
    assert proc.returncode != 0
    assert "SENTINEL_DB_PASSWORD" in out(proc)
    assert "--allow-rotation" in out(proc)


# ---------------------------------------------------------------------------
# --dry-run: report-only, never gates (round-2 fix)
# ---------------------------------------------------------------------------
def test_dry_run_reports_a_changed_key_without_asking_or_reading_stdin(tmp_path):
    """The recorded production invocation always carries [--dry-run]. Before
    this fix, --dry-run skipped compare_secrets_with_host entirely, so the
    rehearsal never rehearsed the one check this whole file is about. Must
    report the change and return 0 with NOTHING on stdin — a prompt here
    would hang a rehearsal that is supposed to be non-interactive."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), dry_run=1, stdin="")
    assert "RC=0" in proc.stdout, out(proc)
    assert "SENTINEL_DB_PASSWORD" in out(proc)
    assert "would get a NEW value" in out(proc)
    assert "dry run" in out(proc).lower()


def test_dry_run_does_not_gate_even_under_assume_yes(tmp_path):
    """A dry run sends nothing, so there is nothing for --allow-rotation to
    authorise and nothing for --yes to refuse. Must report and return 0
    regardless of ASSUME_YES."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), dry_run=1, assume_yes=1, stdin="")
    assert "RC=0" in proc.stdout, out(proc)
    assert "SENTINEL_DB_PASSWORD" in out(proc)


# ---------------------------------------------------------------------------
# Cannot know vs. fine — CLAUDE.md's own distinction
# ---------------------------------------------------------------------------
def test_a_sudo_failure_refuses_rather_than_guessing(tmp_path):
    """If the host cannot be read, that is NOT the same as "nothing would
    change" or "first install" — collapsing "unknown" into "fine" is exactly
    what a monitoring tool must never do. Must stop before anything is
    reported as safe, and must not proceed to packaging.

    Runs under the harness's real `set -euo pipefail` (not a relaxed one): a
    round-1 defect had `remote_out="$(ssh_run ... 2>&1)"` as a bare statement,
    which `set -e` would have killed BEFORE `remote_rc=$?` was ever read —
    this test would still have gone red (no "RC=0"), but for the wrong
    reason, with no die() message at all. Asserting the actual message text
    below is what tells the two apart."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS), sudo_ok=False)
    assert "RC=0" not in proc.stdout
    assert proc.returncode != 0
    assert "would get a NEW value" not in out(proc)
    assert "first install" not in out(proc)
    assert "could not read /etc/sentinel/secrets.env" in out(proc), \
        f"die() was not reached with its message — a bare assignment under set -e \
would kill the script silently instead: {out(proc)!r}"
    assert "sudo -n failed" in out(proc)


# ---------------------------------------------------------------------------
# ssh's own stderr must not contaminate the parsed keys (round-2 fix)
# ---------------------------------------------------------------------------
def test_noisy_ssh_stderr_is_not_parsed_as_a_key(tmp_path):
    """Every ssh_run call in this harness writes a PQ-key-exchange warning to
    its OWN stderr before doing anything else — see the harness's `ssh_run`
    stub. Before this fix, `remote_out="$(ssh_run ... 2>&1)"` merged that
    line into the text parsed as KEY HASH lines, producing a bogus `**` key
    and losing ABSENT detection. First install (host_content=None) is the
    scenario the round-1 report named explicitly: it must still be detected
    correctly, and the warning text must never appear as though it were a
    key name."""
    proc = run(tmp_path, _dump(HOST_SECRETS), None)
    assert "RC=0" in proc.stdout, out(proc)
    assert "first install" in out(proc)
    assert "POST-QUANTUM" not in out(proc).upper() or "WARNING" not in out(proc), \
        "the ssh client's own stderr noise leaked into the comparison's output"
    assert "**" not in out(proc).replace("RC=0", "")


# ---------------------------------------------------------------------------
# Equivalence the installer itself relies on (docs/OPERARE.md §11, step 2)
# ---------------------------------------------------------------------------
def test_a_hand_quoted_local_value_matches_the_unquoted_host_value(tmp_path):
    """install.sh's stdin reader strips one wrapping pair of quotes before it
    ever writes a value to the host (deploy/install.sh, read_stdin_secrets).
    If this comparison did not apply the same strip, a value quoted by hand in
    secrets/.env.local would report as "changed" forever, even immediately
    after a rotation that succeeded — training the operator to expect and
    ignore a warning that never goes away."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD='"OLD-db-password"')
    proc = run(tmp_path, _dump(local), _dump(HOST_SECRETS))
    assert "RC=0" in proc.stdout, out(proc)
    assert "would get a NEW value" not in out(proc), out(proc)


def test_a_hand_quoted_host_value_matches_the_unquoted_local_value(tmp_path):
    """The reverse of the test above, and the gap a round-2 note flagged:
    deploy/install.sh's existing_secret() carries a value on the HOST forward
    VERBATIM, quotes included, whenever a key is not given fresh on stdin —
    this deployment's SENTINEL_BEACON_SECRET and SENTINEL_SHIP_SECRET were
    once written by hand (see secrets/.gitkeep) and could easily be quoted on
    disk today. If REMOTE_SECRETS_SCRIPT hashed that value AS STORED, quotes
    included, while the local side stripped them, an unchanged secret would
    report as "changed" on every single deploy forever — training the
    operator to click through a warning that never means anything."""
    host = dict(HOST_SECRETS, SENTINEL_BEACON_SECRET='"' + HOST_SECRETS["SENTINEL_BEACON_SECRET"] + '"')
    proc = run(tmp_path, _dump(HOST_SECRETS), _dump(host))
    assert "RC=0" in proc.stdout, out(proc)
    assert "would get a NEW value" not in out(proc), out(proc)


def test_a_crlf_local_file_does_not_report_a_false_rotation(tmp_path):
    """A secrets/.env.local saved by a Windows editor. install.sh's stdin
    reader strips a trailing CR before hashing (the same file, the same
    reasoning as test_secrets_preserved.py's CRLF test); if this comparison
    did not, every value in a CRLF-saved file would show as "changed" against
    an identical host, on every single deploy."""
    local_content = "".join(f"{k}={v}\r\n" for k, v in HOST_SECRETS.items())
    proc = run(tmp_path, local_content, _dump(HOST_SECRETS))
    assert "RC=0" in proc.stdout, out(proc)
    assert "would get a NEW value" not in out(proc), out(proc)


def test_comments_and_blank_lines_are_not_keys(tmp_path):
    """The header install.sh writes at the top of secrets.env
    ("# Generated by install.sh at ...") must not be read as a key named `#`
    or as noise that derails the parse of the real keys below it."""
    host_content = "# Generated by install.sh at 2026-07-31T00:00:00Z\n\n" + _dump(HOST_SECRETS)
    proc = run(tmp_path, _dump(HOST_SECRETS), host_content)
    assert "RC=0" in proc.stdout, out(proc)
    assert "no existing key would change" in out(proc)


# ---------------------------------------------------------------------------
# PowerShell twin: the remote script must be the identical shell text
# ---------------------------------------------------------------------------
def test_the_two_wrappers_ship_the_identical_remote_script():
    """deploy.sh and deploy.ps1 each embed a copy of the script that runs ON
    THE HOST to compute hashes. If the two ever drifted, an operator deploying
    from PowerShell would get a different comparison — silently — than one
    deploying from Git Bash, against the very same host."""
    sh_text = DEPLOY_SH.read_text(encoding="utf-8")
    m = re.search(r"<<'REMOTE_SCRIPT'\n(.*?)\nREMOTE_SCRIPT\n\)\"", sh_text, re.S)
    assert m, "REMOTE_SECRETS_SCRIPT heredoc body not found in deploy.sh"
    sh_body = m.group(1)

    ps1_text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    m = re.search(r"\$RemoteSecretsScript = \(@'\n(.*?)\n'@\)", ps1_text, re.S)
    assert m, "$RemoteSecretsScript here-string body not found in deploy.ps1"
    ps1_body = m.group(1)

    assert sh_body == ps1_body, "deploy.sh and deploy.ps1 embed different remote scripts"


# ---------------------------------------------------------------------------
# PowerShell twin: Compare-SecretsWithHost itself
# ---------------------------------------------------------------------------
# The base64/ssh/sudo pipeline is generic and already exercised above — it is
# the same shell text on both sides (see the lockstep test just above). What is
# specific to this wrapper is the PowerShell-side parsing, grouping and
# gating, so Get-SshOutput is stubbed here to return canned "KEY hash" lines
# directly, and the tests below are only about what Compare-SecretsWithHost
# does with them. Get-SshOutput's OWN correctness (the CRLF/Out-String defect)
# is covered separately below, against the REAL function.
PS = shutil.which("powershell.exe") or shutil.which("pwsh")
pytestmark_ps = pytest.mark.skipif(PS is None, reason="no PowerShell available")


def _powershell_function(text: str, name: str) -> str:
    """(body) of `function X { ... }`, by brace depth — see
    tests/unit/test_force_step_list.py, which this is copied from."""
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


def run_ps(tmp_path: Path, local_content: str, *, stub_out: str, stub_rc: int = 0,
          assume_yes: str = "$false", dry_run: str = "$false",
          allow_rotation: str = "$false", allow_rotation_keys: str = "",
          stdin: str = "") -> subprocess.CompletedProcess:
    secrets_file = tmp_path / "local.env"
    secrets_file.write_text(local_content, encoding="utf-8", newline="\n")

    ps1_text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    compare_fn = _powershell_function(ps1_text, "Compare-SecretsWithHost")
    hash_fn = _powershell_function(ps1_text, "Get-ValueHash")
    rotation_fn = _powershell_function(ps1_text, "Test-RotationAllowed")

    # PowerShell's backtick-n escape for a literal newline only expands inside
    # a DOUBLE-quoted string — inside single quotes it is two literal
    # characters, backtick and n, and $remoteOut would arrive as one line.
    stub_out_ps = stub_out.replace("\n", "`n").replace('"', '`"').replace("$", "`$")
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "function Write-Info { param($m) Write-Host \"INFO $m\" }",
        "function Write-Warn { param($m) Write-Host \"WARN $m\" }",
        "function Write-Ok   { param($m) Write-Host \"OK $m\" }",
        "function Die { param($m) Write-Host \"ERR $m\"; exit 9 }",
        f"function Get-ValueHash {{{hash_fn}}}",
        f"$HostName = 'host.invalid'",
        f"$SecretsFile = '{secrets_file.as_posix()}'",
        f"$AssumeYes = {assume_yes}",
        f"$DryRun = {dry_run}",
        f"$AllowRotation = {allow_rotation}",
        f"$allowRotationKeysList = '{allow_rotation_keys}'",
        f"function Test-RotationAllowed {{{rotation_fn}}}",
        # Compare-SecretsWithHost builds a command from this, but Get-SshOutput
        # is stubbed below and never looks at it — its content is irrelevant here.
        "$RemoteSecretsScript = 'unused-in-this-harness'",
        "function Get-SshOutput {",
        "    param([string]$Command)",
        f"    $global:LASTEXITCODE = {stub_rc}",
        f'    return "{stub_out_ps}"',
        "}",
        f"function Compare-SecretsWithHost {{{compare_fn}}}",
        "Compare-SecretsWithHost",
        "Write-Host 'REACHED_END'",
    ])
    return subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=False, input=stdin.encode("utf-8"),
                          cwd=tmp_path)


def _decode(proc: subprocess.CompletedProcess) -> str:
    return proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_an_identical_file_produces_no_warning(tmp_path):
    """Twin of the bash test with the same name: a redeploy of an unchanged
    host must not warn, on either wrapper."""
    local = _dump(HOST_SECRETS)
    stub = "\n".join(f"{k} {_h(v)}" for k, v in HOST_SECRETS.items())
    proc = run_ps(tmp_path, local, stub_out=stub)
    text = _decode(proc)
    assert "REACHED_END" in text, text
    assert "would get a NEW value" not in text
    assert "no existing key would change" in text


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_a_changed_key_is_named_and_gated(tmp_path):
    """Twin of test_a_mixed_file_is_named_key_by_key: PowerShell must name the
    same changed key and stop at the same confirmation gate."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    stub = "\n".join(f"{k} {_h(v)}" for k, v in HOST_SECRETS.items())
    proc = run_ps(tmp_path, _dump(local), stub_out=stub, stdin="NU\n")
    text = _decode(proc)
    assert "SENTINEL_DB_PASSWORD" in text
    assert "would get a NEW value" in text
    assert "REACHED_END" not in text, "the run proceeded past a declined confirmation"
    assert proc.returncode != 0


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_assume_yes_alone_refuses_a_rotation(tmp_path):
    """Twin of the bash test with the same intent: -AssumeYes alone must no
    longer wave a rotation through — that was the round-1 defect."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    stub = "\n".join(f"{k} {_h(v)}" for k, v in HOST_SECRETS.items())
    proc = run_ps(tmp_path, _dump(local), stub_out=stub, assume_yes="$true")
    text = _decode(proc)
    assert "REACHED_END" not in text, text
    assert "SENTINEL_DB_PASSWORD" in text
    assert "-AllowRotation" in text


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_assume_yes_with_allow_rotation_proceeds(tmp_path):
    """Twin of the bash legitimate-scripted-path test: -AssumeYes plus
    -AllowRotation must proceed and still name the key."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    stub = "\n".join(f"{k} {_h(v)}" for k, v in HOST_SECRETS.items())
    proc = run_ps(tmp_path, _dump(local), stub_out=stub, assume_yes="$true", allow_rotation="$true")
    text = _decode(proc)
    assert "REACHED_END" in text, text
    assert "SENTINEL_DB_PASSWORD" in text
    assert "AllowRotation" in text


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_dry_run_reports_without_gating(tmp_path):
    """Twin of the bash dry-run test: -DryRun must report the changed key and
    return without asking, even with nothing on stdin."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD="a-new-password")
    stub = "\n".join(f"{k} {_h(v)}" for k, v in HOST_SECRETS.items())
    proc = run_ps(tmp_path, _dump(local), stub_out=stub, dry_run="$true", stdin="")
    text = _decode(proc)
    assert "REACHED_END" in text, text
    assert "SENTINEL_DB_PASSWORD" in text
    assert "dry run" in text.lower()


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_a_sudo_failure_refuses(tmp_path):
    """Twin of the bash sudo-failure test: a non-zero exit from the stubbed
    transport must stop before anything is reported as safe."""
    local = _dump(HOST_SECRETS)
    proc = run_ps(tmp_path, local, stub_out="sudo: a password is required", stub_rc=1)
    text = _decode(proc)
    assert "REACHED_END" not in text
    assert "would get a NEW value" not in text
    assert "no existing key would change" not in text


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_first_install_with_no_host_secrets_file(tmp_path):
    """Twin of the bash test_a_host_with_no_secrets_file_is_a_first_install_
    not_a_warning: a host with no secrets.env yet must be reported as a first
    install, not as every key rotating away from something. Closes a round-4
    gap: changing `if ($remoteOut -eq 'ABSENT')` to any other literal (e.g.
    'NEVER') stayed green under every PowerShell test that existed before
    this one — none of them ever fed Compare-SecretsWithHost the ABSENT
    sentinel REMOTE_SECRETS_SCRIPT actually prints for a bare host."""
    local = _dump(HOST_SECRETS)
    proc = run_ps(tmp_path, local, stub_out="ABSENT")
    text = _decode(proc)
    assert "REACHED_END" in text, text
    assert "first install" in text
    assert "would get a NEW value" not in text
    assert "only on the host" not in text
    assert "only in the local file" not in text


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_local_quote_strip_matches_unquoted_host_value(tmp_path):
    """Twin of the bash test_a_hand_quoted_local_value_matches_the_unquoted_
    host_value: a hand-quoted value in secrets\\.env.local must hash the same
    as the unquoted value install.sh actually wrote to the host. Closes a
    round-4 gap: removing the local quote strip in Compare-SecretsWithHost
    (the `if ($v.EndsWith('"')) ... if ($v.StartsWith('"')) ...` pair) stayed
    green under every PowerShell test that existed before this one — none of
    them ever fed it a quoted local value, only the bash side had this
    coverage."""
    local = dict(HOST_SECRETS, SENTINEL_DB_PASSWORD='"OLD-db-password"')
    stub = "\n".join(f"{k} {_h(v)}" for k, v in HOST_SECRETS.items())
    proc = run_ps(tmp_path, _dump(local), stub_out=stub)
    text = _decode(proc)
    assert "REACHED_END" in text, text
    assert "would get a NEW value" not in text, text


# ---------------------------------------------------------------------------
# PowerShell twin: Get-SshOutput's own CRLF handling (round-2 fix)
# ---------------------------------------------------------------------------
def _real_ps_function(name: str) -> str:
    ps1_text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    return _powershell_function(ps1_text, name)


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_get_sshoutput_survives_the_real_out_string_crlf_join(tmp_path):
    """The actual round-1 defect: `($out | Out-String).Trim()` on Windows
    PowerShell 5.1 joins array elements with [Environment]::NewLine, i.e.
    CRLF — so a caller that splits the result on "`n" alone (exactly what
    Compare-SecretsWithHost does) gets every line but the last with a
    trailing `\r`. This test calls the SHIPPED Get-SshOutput completely
    unstubbed, with `$ssh` pointed at a REAL nested powershell.exe process
    that emits four lines — not a stub that hands back \n-joined text, which
    is why the existing run_ps-based tests above passed while the shipped
    function did not: Get-SshOutput itself was never exercised.

    Measured directly against the real Out-String before writing the fix:
    CONTAINS_CR=True for the four-line case this test uses; CONTAINS_CR=False
    after joining with "`n" explicitly instead."""
    invoke_capture_fn = _real_ps_function("Invoke-SshCapture")
    get_ssh_output_fn = _real_ps_function("Get-SshOutput")
    lines = ["AAA 1111111111111111", "BBB 2222222222222222",
             "CCC 3333333333333333", "DDD 4444444444444444"]
    inline = "; ".join(f"Write-Output '{l}'" for l in lines)
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        f"$ssh = '{PS}'",
        "$sshArgs = @('-NoProfile', '-Command')",
        f'$target = "{inline}"',
        "$Command = ''",
        f"function Invoke-SshCapture {{{invoke_capture_fn}}}",
        f"function Get-SshOutput {{{get_ssh_output_fn}}}",
        "$result = Get-SshOutput $Command",
        "Write-Host ('CONTAINS_CR=' + $result.Contains([char]13))",
        "Write-Host ('RESULT=' + $result)",
    ])
    proc = subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True, cwd=tmp_path)
    text = proc.stdout + proc.stderr
    assert "CONTAINS_CR=False" in text, text
    for l in lines:
        assert l in text, f"line lost or corrupted in the join/trim: {text!r}"


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_ps1_get_sshoutput_downstream_split_matches_every_line(tmp_path):
    """The consequence, spelled out the way Compare-SecretsWithHost actually
    consumes the result: splitting Get-SshOutput's return value on "`n" alone
    must reproduce every original line byte-for-byte, none of them carrying a
    residual `\r`. Before the fix, only the LAST of four lines matched — the
    exact "only the last hash matched" symptom the round-2 report measured."""
    invoke_capture_fn = _real_ps_function("Invoke-SshCapture")
    get_ssh_output_fn = _real_ps_function("Get-SshOutput")
    lines = ["ANTHROPIC_API_KEY aaaaaaaaaaaaaaaa", "TELEGRAM_BOT_TOKEN bbbbbbbbbbbbbbbb",
             "TELEGRAM_CHAT_ID cccccccccccccccc", "SENTINEL_DB_PASSWORD dddddddddddddddd"]
    inline = "; ".join(f"Write-Output '{l}'" for l in lines)
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        f"$ssh = '{PS}'",
        "$sshArgs = @('-NoProfile', '-Command')",
        f'$target = "{inline}"',
        "$Command = ''",
        f"function Invoke-SshCapture {{{invoke_capture_fn}}}",
        f"function Get-SshOutput {{{get_ssh_output_fn}}}",
        "$result = Get-SshOutput $Command",
        "$segments = @($result -split \"`n\")",
        "Write-Host ('COUNT=' + $segments.Count)",
        "for ($i = 0; $i -lt $segments.Count; $i++) { Write-Host \"SEG${i}=[$($segments[$i])]\" }",
    ])
    proc = subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True, cwd=tmp_path)
    text = proc.stdout + proc.stderr
    assert "COUNT=4" in text, text
    for i, l in enumerate(lines):
        assert f"SEG{i}=[{l}]" in text, \
            f"line {i} did not survive the split unchanged (residual \\r?): {text!r}"


# ---------------------------------------------------------------------------
# PowerShell twin: the transport must survive PRODUCTION's own stderr noise
# (round-4 fix)
# ---------------------------------------------------------------------------
# The round-2 tests above prove Get-SshOutput joins CRLF-free — but the nested
# process they spawn (Write-Output only) never writes to stderr, so they stay
# green while the shipped function dies on the one condition production
# actually presents: `$ErrorActionPreference = 'Stop'` promotes ANY redirected
# stderr line to a terminating NativeCommandError on Windows PowerShell 5.1,
# and this host's OpenSSH 10.2p1 client prints exactly three such lines on
# EVERY connection to production's OpenSSH 8.7 (no post-quantum key exchange).
# These tests spawn a REAL nested powershell.exe that writes those exact three
# lines to stderr before its stdout — in both invocation shapes ssh itself
# uses (-Command for a one-liner, -File for a script) — against the SHIPPED,
# completely unstubbed Invoke-SshCapture / Get-SshOutput / Test-Ssh.
PQ_WARNING_LINES = [
    "** WARNING: connection is not using a post-quantum key exchange algorithm.",
    '** This session may be vulnerable to "store now, decrypt later" attacks.',
    "** The server may need to be upgraded. See https://openssh.com/pq.html",
]


def _write_pq_stub(tmp_path: Path) -> Path:
    """A nested powershell.exe that reproduces production's sshd banner
    verbatim, then two stdout lines — standing in for `$ssh` itself."""
    stub = tmp_path / "pq_stub.ps1"
    body = "\n".join(f"[Console]::Error.WriteLine('{l}')" for l in PQ_WARNING_LINES)
    body += "\nWrite-Output 'stdout-line-1'\nWrite-Output 'stdout-line-2'\n"
    stub.write_text(body, encoding="utf-8", newline="\n")
    return stub


def _harness_for(fn_names: list[str], mode: str, stub_path: Path, command_var: str = "''") -> str:
    """Wires $ssh at a REAL nested powershell.exe emitting the PQ banner,
    inlines the named shipped functions unstubbed, and invokes the caller-
    supplied expression."""
    fns = "\n".join(f"function {n} {{{_real_ps_function(n)}}}" for n in fn_names)
    if mode == "Command":
        args = f"@('-NoProfile', '-Command', \"& '{stub_path.as_posix()}'\")"
    else:
        args = f"@('-NoProfile', '-File', '{stub_path.as_posix()}')"
    return "\n".join([
        "$ErrorActionPreference = 'Stop'",
        f"$ssh = '{PS}'",
        f"$sshArgs = {args}",
        "$target = ''",
        f"$Command = {command_var}",
        fns,
    ])


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
@pytest.mark.parametrize("mode", ["Command", "File"])
def test_ps1_get_sshoutput_survives_real_production_stderr_noise(tmp_path, mode):
    """The point of round 4: Get-SshOutput must not die on the ONE condition
    production presents on every single connection. Before this fix (bare
    `& $ssh ... 2>$null` with no lowered $ErrorActionPreference), this exact
    harness threw `NativeCommandError` with the first PQ line as its message,
    in both -Command and -File mode — reproduced by hand against the old
    function body before writing this test. Must now return the two stdout
    lines and nothing from stderr."""
    stub = _write_pq_stub(tmp_path)
    script = "\n".join([
        _harness_for(["Invoke-SshCapture", "Get-SshOutput"], mode, stub),
        "try {",
        "    $result = Get-SshOutput $Command",
        "    Write-Host ('RESULT=[' + $result + ']')",
        "} catch {",
        "    Write-Host ('THREW=' + $_.Exception.Message)",
        "}",
    ])
    proc = subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True, cwd=tmp_path)
    text = proc.stdout + proc.stderr
    assert "THREW=" not in text, f"Get-SshOutput died on production's own stderr noise ({mode}): {text!r}"
    assert "RESULT=[stdout-line-1\nstdout-line-2]" in text, text
    for l in PQ_WARNING_LINES:
        assert l not in text, f"ssh's own stderr leaked into Get-SshOutput's return value: {text!r}"


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
@pytest.mark.parametrize("mode", ["Command", "File"])
def test_ps1_test_ssh_survives_real_production_stderr_noise(tmp_path, mode):
    """Twin of the test above for Test-Ssh: the very first call the script
    makes (`Test-Ssh -Command 'echo connected'`, the connectivity probe) must
    not die on the PQ banner either — that call runs before anything else,
    on every deploy from this machine."""
    stub = _write_pq_stub(tmp_path)
    script = "\n".join([
        _harness_for(["Invoke-SshCapture", "Test-Ssh"], mode, stub),
        "try {",
        "    $rc = Test-Ssh -Command $Command",
        "    Write-Host ('RC=' + $rc)",
        "} catch {",
        "    Write-Host ('THREW=' + $_.Exception.Message)",
        "}",
    ])
    proc = subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True, cwd=tmp_path)
    text = proc.stdout + proc.stderr
    assert "THREW=" not in text, f"Test-Ssh died on production's own stderr noise ({mode}): {text!r}"
    assert "RC=0" in text, text


# ---------------------------------------------------------------------------
# Every native ssh invocation goes through the one place that knows how
# (round-4 design requirement)
# ---------------------------------------------------------------------------
def _strip_powershell_comments(text: str) -> str:
    """Removes `<# ... #>` block comments and `#`-to-end-of-line comments from
    a PowerShell source, leaving code (including string literals) intact.

    A count of the literal `& $ssh` that does not strip comments cannot tell
    a real bypass from a sentence describing one — a round of this guard
    proved both directions of that wrong: a real bypassing call landing while
    a comment was reworded away left the count unchanged and green, and
    rewording a comment alone (no code touched) turned it red. Comments have
    to come out before anything is counted.

    A `#` INSIDE A STRING LITERAL is not a comment — `Write-Host 'issue #1'`
    must keep its `#`, not have the rest of the line silently discarded. This
    walks the line character by character tracking single- and double-quoted
    strings (with the doubled-quote and backtick escapes each uses) plus
    PowerShell's multi-line here-strings (`@'...'@`, `@"..."@`, whose closing
    delimiter must open the line, matching this file's own `$RemoteSecretsScript`
    block), so a `#` or a `<#`/`#>` sequence inside any of those never ends a
    string early or gets mistaken for a comment marker.

    What a simpler rule (bare `re.sub(r'#.*', '', line)` before counting)
    would miss: exactly this file's `$RemoteSecretsScript` here-string, which
    is bash source FULL of `#` — bash comments (`'#'*`), and shell parameter
    expansions (`${line%$CR}`) that contain no `#` here but could. A naive
    per-line strip has no notion of a here-string spanning many lines, so it
    would happily mangle that block without changing this test's verdict
    either way (it contains no `& $ssh`) — but the same naive rule would also
    mishandle a single-quoted PowerShell string containing `#` earlier on a
    line that later holds a real `& $ssh` call, silently deleting the call
    from the count instead of flagging it. That is the direction that
    matters: a guard that can be fooled into under-counting is a guard a
    bypass can hide behind.

    Not handled, and not needed for this file: nested `<# #>` block comments
    (PowerShell's own parser does not nest them either) and a `#` that is
    itself inside a here-string's own embedded quotes (the here-string state
    below ignores quote characters entirely once inside, by design — the
    whole point of a here-string is that nothing inside it is parsed)."""
    lines = text.split("\n")
    out_lines: list[str] = []
    state = "NONE"  # NONE, BLOCK_COMMENT, HERE_SINGLE, HERE_DOUBLE
    for line in lines:
        if state == "BLOCK_COMMENT":
            idx = line.find("#>")
            if idx == -1:
                out_lines.append("")
                continue
            line = line[idx + 2:]
            state = "NONE"
        elif state == "HERE_SINGLE":
            if line.startswith("'@"):
                line = line[2:]
                state = "NONE"
            else:
                out_lines.append("")
                continue
        elif state == "HERE_DOUBLE":
            if line.startswith('"@'):
                line = line[2:]
                state = "NONE"
            else:
                out_lines.append("")
                continue

        out_chars: list[str] = []
        j, n = 0, len(line)
        in_squote = in_dquote = False
        while j < n:
            ch = line[j]
            two = line[j:j + 2]
            if in_squote:
                out_chars.append(ch)
                if ch == "'":
                    if line[j + 1:j + 2] == "'":
                        out_chars.append("'")
                        j += 2
                        continue
                    in_squote = False
                j += 1
                continue
            if in_dquote:
                if ch == "`" and j + 1 < n:
                    out_chars.append(ch)
                    out_chars.append(line[j + 1])
                    j += 2
                    continue
                out_chars.append(ch)
                if ch == '"':
                    if line[j + 1:j + 2] == '"':
                        out_chars.append('"')
                        j += 2
                        continue
                    in_dquote = False
                j += 1
                continue
            # not inside any string literal
            if two == "@'" and line[j + 2:].strip() == "":
                out_chars.append(two)
                state = "HERE_SINGLE"
                j = n
                break
            if two == '@"' and line[j + 2:].strip() == "":
                out_chars.append(two)
                state = "HERE_DOUBLE"
                j = n
                break
            if two == "<#":
                remainder = line[j:]
                idx = remainder.find("#>")
                if idx != -1:
                    j = j + idx + 2
                    continue
                state = "BLOCK_COMMENT"
                j = n
                break
            if ch == "'":
                in_squote = True
                out_chars.append(ch)
                j += 1
                continue
            if ch == '"':
                in_dquote = True
                out_chars.append(ch)
                j += 1
                continue
            if ch == "#":
                break
            out_chars.append(ch)
            j += 1
        out_lines.append("".join(out_chars))
    return "\n".join(out_lines)


def test_every_native_ssh_call_site_is_accounted_for():
    """Pins the count and location of every REAL `& $ssh` call in deploy.ps1,
    so a fourth call site added later (that bypasses Invoke-SshCapture and
    reintroduces the redirected-stderr bug one call at a time) fails this
    test rather than shipping silently.

    Comments are stripped first (see _strip_powershell_comments): a version
    of this test that counted the raw literal text, including comments, was
    proven wrong in both directions — a real bypassing call landing while one
    comment mention was reworded away kept the raw count unchanged and green,
    and rewording or adding a comment alone (no code touched) changed the raw
    count and went red on a non-defect. Counting only code fixes both: the
    assertion below tracks code, and a comment can say whatever it wants.

    Exactly three real invocations exist today:
      * inside Invoke-SshCapture — the only place that redirects stderr, and
        therefore the only place needing the lowered-$ErrorActionPreference
        guard;
      * inside Invoke-SshLive — deliberately NOT redirected (stdout+stderr
        both inherit the console, so sudo can prompt), and proven safe
        without the guard by test_ps1_invoke_sshlive_shape_needs_no_guard
        below;
      * the top-level piped install command (`Get-Content ... | & $ssh ...`)
        — also not redirected, same reasoning as Invoke-SshLive, proven safe
        by test_ps1_piped_bare_ssh_call_survives_stderr_noise below.
    """
    text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    code = _strip_powershell_comments(text)
    occurrences = [m.start() for m in re.finditer(r"& \$ssh\b", code)]
    assert len(occurrences) == 3, (
        f"expected exactly 3 real & $ssh invocations in code (comments "
        f"excluded); found {len(occurrences)}. A new ssh call site was "
        f"added — route it through Invoke-SshCapture if it redirects "
        f"stderr, or explain here why it does not need to."
    )
    cap_body = _powershell_function(text, "Invoke-SshCapture")
    live_body = _powershell_function(text, "Invoke-SshLive")
    assert "$out = & $ssh @Arguments $Target $Command 2>$null" in cap_body
    assert "& $ssh @a $target $Command" in live_body
    assert "Get-Content $SecretsFile -Raw | & $ssh @sshArgs $target $remoteCmd" in text


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
@pytest.mark.parametrize("mode", ["Command", "File"])
def test_ps1_invoke_sshlive_shape_needs_no_guard(tmp_path, mode):
    """Invoke-SshLive redirects nothing — stdout and stderr both inherit the
    console. Proves that shape alone (no `2>`, no capture) does not throw
    under $ErrorActionPreference = 'Stop' even when the child writes to
    stderr, which is the justification for NOT routing it through
    Invoke-SshCapture (that helper always adds a `2>$null` this call must not
    have — it would swallow the sudo prompt this function exists to show)."""
    stub = _write_pq_stub(tmp_path)
    script = "\n".join([
        _harness_for(["Invoke-SshLive"], mode, stub),
        "try {",
        "    Invoke-SshLive -Command $Command",
        "    Write-Host ('RC=' + $LASTEXITCODE)",
        "} catch {",
        "    Write-Host ('THREW=' + $_.Exception.Message)",
        "}",
    ])
    proc = subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True, cwd=tmp_path)
    text = proc.stdout + proc.stderr
    assert "THREW=" not in text, f"Invoke-SshLive threw on inherited-console stderr ({mode}): {text!r}"
    assert "RC=0" in text, text


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
@pytest.mark.parametrize("mode", ["Command", "File"])
def test_ps1_piped_bare_ssh_call_survives_stderr_noise(tmp_path, mode):
    """The third real call site — the install command's
    `Get-Content ... -Raw | & $ssh ...`, which pipes the secrets file's
    content into ssh's stdin and inherits the console for output, exactly
    like Invoke-SshLive. Reproduces that EXACT shape (piped input, no `2>`,
    no capture) against the real PQ-noise stub, standing in for `$ssh`."""
    stub = _write_pq_stub(tmp_path)
    if mode == "Command":
        args_literal = f"@('-NoProfile', '-Command', \"& '{stub.as_posix()}'\")"
    else:
        args_literal = f"@('-NoProfile', '-File', '{stub.as_posix()}')"
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        f"$ssh = '{PS}'",
        f"$sshArgs = {args_literal}",
        "$target = ''",
        "$remoteCmd = ''",
        "try {",
        "    'fake-secrets-content' | & $ssh @sshArgs $target $remoteCmd",
        "    Write-Host ('RC=' + $LASTEXITCODE)",
        "} catch {",
        "    Write-Host ('THREW=' + $_.Exception.Message)",
        "}",
    ])
    proc = subprocess.run([PS, "-NoProfile", "-Command", script],
                          capture_output=True, text=True, cwd=tmp_path)
    text = proc.stdout + proc.stderr
    assert "THREW=" not in text, f"piped bare ssh call threw on stderr noise ({mode}): {text!r}"
    assert "RC=0" in text, text
