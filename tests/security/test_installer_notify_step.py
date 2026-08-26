"""Step 39 must always come back, and must never claim more than it proved.

The last step of the installer sends one Telegram message, because receiving it
is the only end-to-end proof that alerting works. What shipped instead:

    "${SENTINEL_PREFIX}/bin/sentinel" telegram --send-test --message "…" \\
        2>/dev/null && ok "Telegram test message sent" \\
        || info "Telegram test not available in this build (arrives in P4)"

`--send-test` was defined nowhere. The CLI dropped flags it did not recognise,
so this ran `sentinel telegram` — the long-polling bot — as a second poller
against the token the live unit was already using. It printed neither branch,
because it never returned. Both the `&&` and the `||` were written for a
command that ends; this one succeeded at doing the wrong thing forever.

Two costs, and the second is the expensive one:

  * every deploy hung here and was killed by hand;
  * `scripts/deploy.sh` removes /tmp/sentinel-deploy-* only on the success
    path, so the kill skipped it. docs/INTARIRE.md §0 records three of those
    directories left on the host, each holding credentiale.txt at mode 644 with
    the Anthropic key, the bot token and the chat id — readable by every local
    account for nine days.

These tests run the SHIPPED step 39, extracted verbatim between the `# --- 39`
marker and the `main()` banner, against a fake `sentinel` binary whose exit code
and behaviour each case chooses. What is asserted is what the operator sees: a
verdict line, always, and one that matches what actually happened.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "deploy" / "install.sh"
BASH = shutil.which("bash")

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="no bash on PATH")]


def step39_source() -> str:
    """Step 39 as shipped, not a copy of it.

    Taken between the section marker and the `main()` banner so the timeout
    constant travels with the function. If the markers move this raises, rather
    than silently testing an empty string — a mistake this repository has paid
    for before.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(r"^# --- 39 -+\n(.*?)^# ={20,}$", text, re.S | re.M)
    assert match, "cannot find the step 39 block in install.sh"
    body = match.group(1)
    assert "step_notify()" in body, "step 39 no longer defines step_notify"
    assert "NOTIFY_TIMEOUT_S" in body, "the timeout constant left the block"
    return body


HARNESS = """
source ./lib/common.sh
{step39}

SENTINEL_PREFIX="$PREFIX"
DOMAIN="dashboard.example"
NOTIFY_TIMEOUT_S={timeout}
step_notify
printf 'STEP_RC=%s\\n' "$?"
printf 'WARN_COUNT=%s\\n' "$WARN_COUNT"
"""

FAKE_SENTINEL = """#!/usr/bin/env bash
# Records what the step actually invoked, then behaves as MODE says.
printf '%s\\n' "$*" > "$ARGV_FILE"
case "$MODE" in
    ok)             exit 0 ;;
    notconfigured)  printf 'telegram is disabled in config\\n'; exit 78 ;;
    refused)        printf 'chat 222: FAILED - Bad Request: chat not found\\n' >&2
                    exit 1 ;;
    # exec, so the fake process IS sleep and `timeout` can end it with one
    # signal. A bash parent waiting on a child would only die after --kill-after.
    hang)           exec sleep 30 ;;
esac
exit 9
"""


def run_step_notify(tmp_path: Path, mode: str, timeout_s: int = 5,
                    version: str | None = "1.4.2") -> dict:
    prefix = tmp_path / "opt" / "sentinel"
    (prefix / "bin").mkdir(parents=True)
    if version is not None:
        (prefix / "VERSION").write_text(version + "\n", encoding="utf-8")

    fake = prefix / "bin" / "sentinel"
    fake.write_text(FAKE_SENTINEL, encoding="utf-8", newline="\n")
    fake.chmod(0o755)

    argv_file = tmp_path / "argv.txt"
    script = tmp_path / "harness.sh"
    # A file, not `bash -c`: on Windows a script this size arrives mangled
    # through CreateProcess's command line and bash then reports a syntax error
    # in code that is fine.
    script.write_text(HARNESS.format(step39=step39_source(), timeout=timeout_s),
                      encoding="utf-8", newline="\n")

    started = time.monotonic()
    proc = subprocess.run(
        [BASH, str(script).replace("\\", "/")],
        cwd=REPO / "deploy", capture_output=True, text=True,
        # Generous, and deliberately not the assertion: the point of the step's
        # own timeout is that this one is never reached. If it is, the test
        # fails on elapsed time below with a readable message instead of here.
        timeout=120,
        env={**os.environ, "NO_COLOR": "1",
             "PREFIX": str(prefix).replace("\\", "/"),
             "MODE": mode,
             "ARGV_FILE": str(argv_file).replace("\\", "/")},
    )
    return {
        "proc": proc,
        "out": proc.stdout + proc.stderr,
        "elapsed": time.monotonic() - started,
        "argv": argv_file.read_text(encoding="utf-8") if argv_file.exists() else "",
    }


# ---------------------------------------------------------------------------
# The hang — the defect itself
# ---------------------------------------------------------------------------
def test_a_command_that_never_returns_cannot_hold_the_installer(tmp_path):
    """This is the nine-day credential exposure, reproduced.

    A `sentinel telegram` that keeps running (which is exactly what the old
    invocation did) must not stop the installer from finishing its last step.
    Unbounded, the operator kills the deploy, and the kill is what skips
    deploy.sh's removal of /tmp/sentinel-deploy-*/credentiale.txt.
    """
    result = run_step_notify(tmp_path, mode="hang", timeout_s=3)

    assert result["elapsed"] < 30, "step 39 did not come back on its own"
    # And it really was the timeout that ended it: a fake that failed to start
    # would return instantly and this test would pass while proving nothing.
    assert result["elapsed"] >= 3, "the command did not run for its full budget"
    assert "[!]" in result["out"], "a killed test send produced no warning"
    assert "UNPROVEN" in result["out"]
    assert "STEP_RC=0" in result["out"], "the step aborted the install"


def test_a_hang_is_never_reported_as_a_send_or_as_absent(tmp_path):
    """The old code printed neither `ok` nor `info` and the operator was left
    reading a log that simply stopped. Silence is the one verdict this step is
    not allowed to give."""
    result = run_step_notify(tmp_path, mode="hang", timeout_s=3)

    assert "[+]" not in result["out"], "a hang was reported as a delivered message"
    assert "not available in this build" not in result["out"]
    assert "WARN_COUNT=1" in result["out"], "the warning was not counted"


# ---------------------------------------------------------------------------
# The verdicts
# ---------------------------------------------------------------------------
def test_a_delivered_message_is_the_only_thing_reported_as_delivered(tmp_path):
    result = run_step_notify(tmp_path, mode="ok")

    assert "[+]" in result["out"]
    assert "[!]" not in result["out"]
    assert "WARN_COUNT=0" in result["out"]


def test_the_step_asks_for_a_test_send_and_nothing_else(tmp_path):
    """If the invocation drifts from the flag the service defines, the CLI
    starts the bot again. The argv is recorded by the fake, so this is what was
    really passed, not what the script appears to say."""
    result = run_step_notify(tmp_path, mode="ok")

    argv = result["argv"]
    assert argv.startswith("telegram --send-test --message "), argv
    assert "1.4.2" in argv, "the version never reached the message"
    assert "dashboard.example" in argv, "the dashboard URL never reached the message"


def test_telegram_switched_off_is_not_a_warning(tmp_path):
    """Exit 78 means the operator turned Telegram off. Warning about it trains
    them to ignore the warnings that matter."""
    result = run_step_notify(tmp_path, mode="notconfigured")

    assert "[.]" in result["out"]
    assert "[!]" not in result["out"]
    assert "[+]" not in result["out"], "nothing was sent, so nothing was proved"


def test_a_refusal_from_telegram_warns_and_keeps_the_reason(tmp_path):
    """The old line sent stderr to /dev/null. "chat not found" is the entire
    diagnostic — without it the operator knows only that something failed."""
    result = run_step_notify(tmp_path, mode="refused")

    assert "[!]" in result["out"]
    assert "chat not found" in result["out"], "the reason was discarded"
    assert "[+]" not in result["out"]


def test_a_missing_version_file_still_produces_a_verdict(tmp_path):
    """`set -e` plus a bare `$(cat VERSION)` ends the function with no output at
    all. On a resumed install that file may not be there yet, and the step
    would go quiet for a reason that has nothing to do with Telegram."""
    result = run_step_notify(tmp_path, mode="ok", version=None)

    assert "[+]" in result["out"], result["out"]
    assert "unknown" in result["argv"]


# ---------------------------------------------------------------------------
# Static properties of the shipped step
# ---------------------------------------------------------------------------
def test_the_step_does_not_discard_stderr():
    """The `2>/dev/null` that hid the failure is not allowed back."""
    body = step39_source()
    invocation = re.search(r"timeout --kill-after.*?\|\| rc=\$\?", body, re.S)
    assert invocation, "the guarded invocation is not where this test expects it"
    assert "/dev/null" not in invocation.group(0), \
        "the test send's output is being discarded again"


def test_the_timeout_is_bounded_and_used():
    """A constant nothing reads is decoration. This asserts the step invokes
    `timeout` with it."""
    body = step39_source()
    match = re.search(r"^NOTIFY_TIMEOUT_S=(\d+)$", body, re.M)
    assert match, "NOTIFY_TIMEOUT_S is not a plain integer"
    assert 10 <= int(match.group(1)) <= 300
    assert re.search(r'timeout --kill-after=\d+s "\$\{NOTIFY_TIMEOUT_S\}s"', body), \
        "the step does not run the command under timeout"
