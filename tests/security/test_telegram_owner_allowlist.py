"""Step 42 (`telegram_owner`) closes the exposure CLAUDE.md opens with: on a
host installed before `telegram.allowed_user_ids` existed, `allowed_chat_ids`
names a GROUP and nothing narrows it to a person. `_authorized` in
sentinel/telegram/bot.py already does the right thing the moment the key is
there — these tests are not about that function. They are about the one thing
standing between it and a live host: a writer that has to change exactly one
line of a file it did not create and nobody wants rewritten, then prove the
daemon it restarts actually picked the new line up.

Every test below names the failure it prevents, in the docstring, in terms of
what goes wrong for the operator. `test_a_genuinely_block_form_value_is_left_
alone` documents a bug this file's own falsification pass found: the first
draft of `telegram_allowed_user_ids_is_block_form` reported "not ambiguous" on
every block-form input, because an `exit 0` from inside an awk action runs the
END block on its way out, and that END block had an unconditional `exit 1`
that clobbered it. Reintroducing that one-line defect is exactly what this
test is for.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "deploy" / "install.sh"
INSTALL_TEXT = INSTALL.read_text(encoding="utf-8")

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipsește din PATH")]


def _func(name: str) -> str:
    """A single named function, shipped, not a copy of it."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", INSTALL_TEXT, re.S | re.M)
    assert match, f"funcția {name} nu mai există în deploy/install.sh"
    return match.group(0)


def _step42_source() -> str:
    match = re.search(
        r"^# --- 42 -+\n(.*?)\n# -{3,}\n# Ce mai stă",
        INSTALL_TEXT, re.S | re.M)
    assert match, "cannot find the step 42 block in install.sh"
    body = match.group(1)
    assert "step_telegram_owner()" in body
    return body


# Sourced ahead of the step: `existing_secret` lives in step 27's own block,
# not step 42's, and step_telegram_owner calls it as the fallback path when
# the secret does not arrive on stdin this run.
STEP42 = _func("existing_secret") + "\n" + _step42_source()


def _write_exec(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


REWRITE_HELPERS = (_func("telegram_allowed_user_ids_indent") + "\n"
                    + _func("telegram_allowed_user_ids_is_block_form") + "\n"
                    + _func("telegram_allowed_user_ids_rewrite"))


def _rewrite(tmp_path: Path, yaml_text: str, newval: str) -> str:
    """Runs `telegram_allowed_user_ids_rewrite` DIRECTLY, bypassing
    `step_telegram_owner` and — crucially — `sentinel.config.load_config`.

    A fixture built to probe this one awk function in isolation (a foreign
    top-level section, an unusual block-form shape) is not a document the
    real Config schema was ever meant to validate — `load_config` refuses
    ANY unrecognised top-level or nested key outright ("unknown
    configuration key"), which would reject a probe fixture for a reason
    that has nothing to do with what is being tested here, and mask the
    thing the fixture exists to catch. Going straight at the awk function
    tests the invariant it actually owns: what it does to bytes, not
    whether the result happens to satisfy an unrelated dataclass.
    """
    src = tmp_path / "probe.yaml"
    src.write_text(yaml_text, encoding="utf-8", newline="\n")
    src_posix = str(src).replace("\\", "/")
    script = tmp_path / "probe.sh"
    script.write_text(
        "source ./lib/common.sh\n" + REWRITE_HELPERS + "\n"
        f'indent="$(telegram_allowed_user_ids_indent \'{src_posix}\')"\n'
        f'telegram_allowed_user_ids_rewrite \'{src_posix}\' "$indent" \'{newval}\'\n',
        encoding="utf-8", newline="\n")
    proc = subprocess.run([BASH, str(script).replace("\\", "/")],
                          cwd=REPO / "deploy", capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          env={**os.environ, "NO_COLOR": "1"})
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _make_venv(root: Path, *, fail_from_call: int | None = None,
                counter: Path | None = None, import_broken: bool = False) -> None:
    """A `venv/bin/python` that really imports `sentinel.config` — the same
    loader sentinel-telegram calls on itself — pointed at THIS repo, through
    THIS interpreter, so the config-loads-with-owner check is exercised for
    real rather than stubbed into meaninglessness.

    The wrapper only puts this repo on the interpreter's `sys.path` when its
    OWN incoming `PYTHONPATH` equals `"${root}/lib"` — the exact value
    `telegram_config_loads_with_owner` is supposed to set via
    `env PYTHONPATH="${SENTINEL_PREFIX}/lib"` before invoking the venv
    python, mirroring where the real package sits on both live hosts (no
    site-packages install, no `.pth`). `_run` deliberately does NOT export
    `PYTHONPATH` into the harness's own environment, so this repo is
    reachable from the stub ONLY through the path install.sh's own code sets
    — deleting that `env PYTHONPATH=…` from install.sh makes every call land
    in the `else` branch below and fail to import `sentinel.config` for
    real, the same `No module named 'sentinel'` both live hosts gave the
    verifier when probed directly.

    `import_broken=True` skips that gate entirely and NEVER puts the repo on
    the path, regardless of what `PYTHONPATH` install.sh sets — simulating
    "the venv or sentinel.config cannot be reached from here" for a reason
    that has nothing to do with this one env var (a broken venv, a missing
    dependency), which is the rc=2 branch's own stated scenario.

    `fail_from_call` makes the Nth-and-later invocation disagree instead of
    delegating to the real interpreter. `telegram_config_loads_with_owner` is
    called twice by a successful run — once against the CANDIDATE before
    `install`, once against the file actually on disk after the restart
    settles — and in ordinary operation those two calls can only ever agree,
    because `install` copies the validated candidate byte for byte. That makes
    the second call's own `die` unreachable from any fixture alone; this is
    what makes it reachable, so its removal is something a test can see.
    """
    wrapper = root / "venv" / "bin" / "python"
    lib_path = str(root / "lib").replace("\\", "/")
    repo_path = str(REPO).replace("\\", "/")
    if import_broken:
        gated_exec = f'exec "{sys.executable}" "$@"\n'
    else:
        gated_exec = (
            f'if [[ "$PYTHONPATH" == "{lib_path}" ]]; then\n'
            f'    exec env PYTHONPATH="{repo_path}" "{sys.executable}" "$@"\n'
            "else\n"
            f'    exec "{sys.executable}" "$@"\n'
            "fi\n"
        )
    if fail_from_call is None:
        body = "#!/usr/bin/env bash\n" + gated_exec
    else:
        idx_path = str(counter).replace("\\", "/")
        body = (
            "#!/usr/bin/env bash\n"
            f'n=$(cat "{idx_path}" 2>/dev/null || echo 0)\n'
            f'echo $((n + 1)) > "{idx_path}"\n'
            f'if (( n + 1 >= {fail_from_call} )); then\n'
            '    echo "stub: loader disagrees on this call" >&2\n'
            "    exit 1\n"
            "fi\n"
            + gated_exec
        )
    _write_exec(wrapper, body.replace("\\", "/"))


# ---------------------------------------------------------------------------
# Realistic fixture: the template's telegram: block, with an invented (never
# real) group chat id and no allowed_user_ids — the exact shape both live
# hosts were on, per the task that opened this change. No id here is one a
# real Telegram account could hold in this file; that is deliberate.
# ---------------------------------------------------------------------------
FIXTURE_NO_KEY = """telegram:
  enabled: true
  allowed_chat_ids:
    - -1000000000042     # a GROUP
  owner_chat_id: -1000000000042
  operator_chat_ids: []
  viewer_chat_ids: []

  quiet_hours: null
  timezone: null
  min_severity: medium
  digest_threshold: 10
  rate_limit_per_minute: 30
  callback_ttl_s: 600

  require_pin_for_apply: false

web:
  domain: null
"""

OWNER_ID = "918273645"  # invented, ten digits, never a real account


def _run(tmp_path: Path, fixture: str | None, *, stdin_user_id: str | None,
          on_disk_secret: str | None = None,
          telegram_unit_present: bool = False, telegram_unit_active: bool = False,
          is_active_output: str = "active", nrestarts_sequence: str = "0",
          restart_rc: int = 0, settle_s: int = 1,
          python_fails_from_call: int | None = None,
          python_import_broken: bool = False,
          cat_fails_on_target: bool = False,
          rewrite_stub: str | None = None) -> dict:
    """`cat_fails_on_target` and `rewrite_stub` reach the two refusal branches
    no fixture alone can produce.

    `cat_fails_on_target` stubs `cat` (an external command, the same
    executable-boundary technique already used for `install`/`systemctl`/
    `journalctl` below) to fail ONLY for `$target`'s own path, everything else
    still runs the real `cat`. A real chmod cannot stand in for this: measured
    directly in this repository's own dev environment, `chmod 000` on a file
    does not stop `cat` from reading it, so a fixture relying on real
    permissions would be green for the wrong reason — see
    docs on `_assert_check`'s `fail_on` stub in
    tests/security/test_installer_state_markers.py, which hits the same wall
    and solves it the same way.

    `rewrite_stub` redefines `telegram_allowed_user_ids_rewrite` itself,
    AFTER it is sourced, the same way this harness already shadows
    `closing_note`. `"fails"` makes it return 1 with no output — the awk
    script producing a real nonzero exit is not reproducible from a fixture,
    since `telegram_allowed_user_ids_rewrite`'s own awk has no syntax path a
    valid `$indent`/`$newval` can reach; the caller's `if ! desired=…` guard
    still has to be exercised, so this stands in for whatever real failure
    (disk full, a killed subshell) would produce the same exit status.
    `"empty"` makes it return 0 with no output, reaching the SEPARATE
    "rewrite succeeded but produced nothing" guard right after it — the two
    are different failure shapes in the source (nonzero exit vs. empty
    stdout) and need different stubs to tell apart.
    """
    cfg = tmp_path / "etc"
    cfg.mkdir(parents=True, exist_ok=True)
    target = cfg / "sentinel.yaml"
    if fixture is not None:
        target.write_text(fixture, encoding="utf-8", newline="\n")

    if on_disk_secret is not None:
        (cfg / "secrets.env").write_text(
            f"TELEGRAM_OWNER_USER_ID={on_disk_secret}\n", encoding="utf-8", newline="\n")

    prefix = tmp_path / "opt"
    _make_venv(prefix, fail_from_call=python_fails_from_call,
               counter=tmp_path / "pyidx", import_broken=python_import_broken)

    bin_dir = tmp_path / "bin"
    # Truncated, not just created: a test that calls `_run` twice against the
    # SAME tmp_path (to prove idempotency across two passes) would otherwise
    # see run 1's calls still sitting in this file during run 2's assertions
    # — a test-harness bug that looks exactly like the installer not being
    # idempotent. `.nidx` (the NRestarts call counter) gets the same reset,
    # for the identical reason.
    calls = tmp_path / "calls.txt"
    calls.write_text("", encoding="utf-8")
    idx_file = Path(f"{calls}.nidx")
    idx_file.unlink(missing_ok=True)

    # `install` needs to be a real file copy: the shipped code chowns to
    # root:sentinel with -o/-g, which this test does not run as root for.
    _write_exec(bin_dir / "install", (
        "#!/usr/bin/env bash\n"
        "printf 'install %s\\n' \"$*\" >> \"$CALLS\"\n"
        'args=("$@")\n'
        'n=${#args[@]}\n'
        'cp "${args[$((n-2))]}" "${args[$((n-1))]}"\n'
    ))
    _write_exec(bin_dir / "journalctl", (
        "#!/usr/bin/env bash\n"
        "printf 'journalctl %s\\n' \"$*\" >> \"$CALLS\"\n"
    ))

    if cat_fails_on_target:
        real_cat = shutil.which("cat")
        assert real_cat, "no real 'cat' found on this machine's PATH to delegate to"
        target_posix = str(target).replace("\\", "/")
        _write_exec(bin_dir / "cat", (
            "#!/usr/bin/env bash\n"
            f'[[ "$1" == "{target_posix}" ]] && exit 1\n'
            f'exec "{real_cat.replace(chr(92), "/")}" "$@"\n'
        ))

    # systemctl, scripted per test. The unit's existence is answered through
    # `list-unit-files`, not a real path under /etc/systemd/system — see the
    # comment beside that check in install.sh for why: it is the one fact this
    # step needs that crosses an executable boundary a test can actually stand
    # in front of. NRestarts is a small sequence, one value per call, so a
    # test can make it climb mid-settle-loop exactly the way a real crash loop
    # would, without a second stubbing mechanism.
    list_line = "sentinel-telegram.service enabled" if telegram_unit_present else ""
    active_rc = "0" if telegram_unit_active else "3"
    systemctl_body = f"""#!/usr/bin/env bash
printf 'systemctl %s\\n' "$*" >> "$CALLS"
case "$*" in
    "list-unit-files sentinel-telegram.service --no-legend --no-pager")
        printf '%s\\n' {list_line!r}
        exit 0 ;;
    "is-active --quiet sentinel-telegram")
        exit {active_rc} ;;
    "is-active sentinel-telegram")
        printf '%s\\n' {is_active_output!r}
        exit {active_rc} ;;
    "restart sentinel-telegram")
        exit {restart_rc} ;;
    "show sentinel-telegram -p NRestarts --value")
        idx_file="${{CALLS}}.nidx"
        idx=$(cat "$idx_file" 2>/dev/null || echo 0)
        echo $((idx + 1)) > "$idx_file"
        values=({nrestarts_sequence})
        n=${{#values[@]}}
        (( idx >= n )) && idx=$((n - 1))
        printf '%s\\n' "${{values[$idx]}}"
        exit 0 ;;
esac
exit 0
"""
    _write_exec(bin_dir / "systemctl", systemctl_body)

    rewrite_override = ""
    if rewrite_stub == "fails":
        rewrite_override = "telegram_allowed_user_ids_rewrite() { return 1; }\n"
    elif rewrite_stub == "empty":
        rewrite_override = "telegram_allowed_user_ids_rewrite() { return 0; }\n"
    elif rewrite_stub is not None:
        raise ValueError(f"unknown rewrite_stub {rewrite_stub!r}")

    harness = f"""
source ./lib/common.sh
{STEP42}

{rewrite_override}
closing_note() {{ printf 'CLOSING_NOTE:%s\\n' "$1" >> "$CALLS"; }}

declare -A SECRETS=({'[TELEGRAM_OWNER_USER_ID]=' + repr(stdin_user_id).replace("'", '"') if stdin_user_id is not None else ''})
SERVICE_SETTLE_S={settle_s}
step_telegram_owner
"""
    script_path = tmp_path / "harness.sh"
    script_path.write_text(harness, encoding="utf-8", newline="\n")

    # PYTHONPATH is deliberately ABSENT here — not just left off the literal
    # dict, but stripped from the inherited environment too, in case the
    # process running pytest itself has one set. F1 was invisible to this
    # file precisely because this dict used to export PYTHONPATH=REPO
    # unconditionally: the stub interpreter then imported `sentinel` no
    # matter what install.sh's own code set or failed to set, so deleting
    # install.sh's `env PYTHONPATH="${SENTINEL_PREFIX}/lib"` on the call
    # (deploy/install.sh, telegram_config_loads_with_owner) was invisible to
    # every test in this file. Reachability of this repo's `sentinel` package
    # now travels ONLY through _make_venv's wrapper, gated on the exact
    # PYTHONPATH value install.sh's own code is supposed to set.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update({
        "NO_COLOR": "1",
        "SENTINEL_CONFIG_DIR": str(cfg).replace("\\", "/"),
        "SENTINEL_PREFIX": str(prefix).replace("\\", "/"),
        "SENTINEL_USER": "sentinel",
        "CALLS": str(calls).replace("\\", "/"),
        "PATH": str(bin_dir).replace("\\", "/") + os.pathsep + os.environ.get("PATH", ""),
    })
    proc = subprocess.run(
        [BASH, str(script_path).replace("\\", "/")],
        cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    result_yaml = target.read_text(encoding="utf-8") if target.exists() else None
    calls_text = calls.read_text(encoding="utf-8") if calls.exists() else ""
    return {"proc": proc, "yaml": result_yaml, "calls": calls_text, "target": target}


def test_absent_secret_is_a_clean_noop(tmp_path):
    """No TELEGRAM_OWNER_USER_ID anywhere: the install must not fail, the
    live file must not move a byte, and the operator has to be told — silently
    leaving a GROUP in command of two production hosts is the exact exposure
    this step exists to close."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=None)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == FIXTURE_NO_KEY, "the file was touched with no secret supplied"
    assert "TELEGRAM_OWNER_USER_ID" in out["proc"].stderr
    assert "CLOSING_NOTE:" in out["calls"], "the operator is not told at the end of the run either"
    assert "install " not in out["calls"]
    assert "systemctl restart" not in out["calls"]


def test_a_non_numeric_secret_is_rejected_not_embedded(tmp_path):
    """A typo in secrets/.env.local must not become invalid — or worse,
    attacker-shaped — YAML written straight into a live sentinel.yaml.

    The message asserted here is the GUARD's own ("nu arată ca un id
    numeric"), not the loader's generic "candidatul nu se încarcă". The
    loader (`sentinel.config._coerce_list_items`) already requires an int
    and would refuse this value on its own — so a test that only checked
    "file unchanged, install not called" would stay green even if the whole
    digit-shape guard at :6415 were deleted; this checks the thing the guard
    specifically exists to say, before the loader is ever asked."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id="12ab; rm -rf")
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == FIXTURE_NO_KEY
    assert "install " not in out["calls"]
    assert "nu arată ca un id numeric" in out["proc"].stderr
    assert "CLOSING_NOTE:" in out["calls"], "no closing note on a refusal the operator must see"


def test_fullwidth_digits_are_not_ascii_digits(tmp_path):
    """A value made only of fullwidth digits must be refused, not embedded in
    the YAML this step writes.

    Earlier drafts of this test (and of the comment beside the guard in
    install.sh) claimed `[0-9]` inside `[[ =~ ]]` is, under a real glibc
    UTF-8 locale, a collation class that also matches fullwidth digits. That
    claim was checked directly on both live production hosts (en_US.UTF-8,
    C.UTF-8, en_US.utf8, C; glibc 2.34 and 2.39) on 25 September 2026 and was
    WRONG: `[[ "９１８" =~ ^[0-9]+$ ]]` is `nomatch` in every one of those
    combinations, same as in this environment. The guard is not defending
    against that; it exists because `sentinel.config`'s own loader would
    refuse this value too but say only "candidatul nu se încarcă", telling
    the operator nothing about what is actually wrong with the secret — so
    this asserts the GUARD's own diagnostic text, not just "nothing bad
    happened", which would stay green even with the guard deleted (the
    loader catches a non-int value regardless)."""
    fullwidth = "９１８２７３６４５"  # "918273645"
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=fullwidth)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == FIXTURE_NO_KEY, "a fullwidth-digit id reached the config file"
    assert "install " not in out["calls"]
    assert "nu arată ca un id numeric" in out["proc"].stderr
    assert "CLOSING_NOTE:" in out["calls"], "no closing note on a refusal the operator must see"


def test_key_absent_is_inserted_and_nothing_else_changes(tmp_path):
    """The documented case on both live hosts: the key is not in the file at
    all. Every other byte — comments, blank lines, unrelated sections — has to
    survive; only one line may appear, and it must land NEXT TO the block it
    belongs to.

    FIXTURE_NO_KEY has the exact shape both live hosts do: a blank line
    separates `telegram:`'s last key from `web:`. Checking only "one line
    added, nothing else changed" (set membership, position-blind) would stay
    green even if that line were inserted on the WRONG side of the blank
    line — directly above `web:` instead of directly below
    `require_pin_for_apply: false` — which is valid YAML but visually
    attaches the new allowed_user_ids to the wrong section for whoever reads
    the file next. This checks the exact index, not just the exact set."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    before = FIXTURE_NO_KEY.splitlines()
    after = out["yaml"].splitlines()
    assert len(after) == len(before) + 1, "more than one logical line changed"
    added = [l for l in after if l not in before]
    assert added == [f"  allowed_user_ids: [{OWNER_ID}]"], added
    removed = [l for l in before if l not in after]
    assert removed == [], f"a pre-existing line was altered: {removed}"
    anchor = before.index("  require_pin_for_apply: false")
    assert after[anchor + 1] == f"  allowed_user_ids: [{OWNER_ID}]", (
        "the new line did not land directly after telegram:'s last key — "
        f"got {after[anchor:anchor + 3]!r}")
    assert after[anchor + 2] == "", "the blank line separating telegram: from web: moved"
    assert after[anchor + 3] == "web:", "the new line ended up on the wrong side of the blank line"


def test_a_successful_write_names_the_recovery_path(tmp_path):
    """A wrong id here locks everyone — including the real operator — out of
    commands in the only chat these hosts allow (a GROUP, no private chat
    listed). The lockout has to be discoverable at the moment it might be
    created, not left for whoever finds it later; see the closing_note the
    task asked this step to make discoverable."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "CLOSING_NOTE:" in out["calls"]
    assert "TELEGRAM_OWNER_USER_ID" in out["calls"]
    assert "redeployeaz" in out["calls"] or "restart sentinel-telegram" in out["calls"]


def test_key_present_empty_converges(tmp_path):
    """`allowed_user_ids: []` — present, written by an operator or a past
    partial edit, but empty — must converge to the owner, not be left as the
    all-chats-allowed default it currently reads as."""
    fixture = FIXTURE_NO_KEY.replace(
        "  viewer_chat_ids: []\n", "  viewer_chat_ids: []\n  allowed_user_ids: []\n")
    out = _run(tmp_path, fixture, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    before, after = fixture.splitlines(), out["yaml"].splitlines()
    assert len(before) == len(after), "a line was added or removed instead of replaced"
    diffs = [(b, a) for b, a in zip(before, after) if b != a]
    assert diffs == [("  allowed_user_ids: []", f"  allowed_user_ids: [{OWNER_ID}]")], diffs


def test_key_present_different_value_converges_and_keeps_its_comment(tmp_path):
    """A stale id from a previous owner, WITH a hand-written trailing comment.
    The comment is not this step's business to delete."""
    fixture = FIXTURE_NO_KEY.replace(
        "  viewer_chat_ids: []\n",
        "  viewer_chat_ids: []\n  allowed_user_ids: [111111111]  # former operator\n")
    out = _run(tmp_path, fixture, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    before, after = fixture.splitlines(), out["yaml"].splitlines()
    assert len(before) == len(after)
    diffs = [(b, a) for b, a in zip(before, after) if b != a]
    assert diffs == [
        ("  allowed_user_ids: [111111111]  # former operator",
         f"  allowed_user_ids: [{OWNER_ID}]  # former operator"),
    ], diffs


def test_already_correct_is_a_noop_no_write_no_restart(tmp_path):
    """Idempotency, checked the way the task asks for it: run against a file
    that already says the right thing, and NOTHING happens — no `install`, no
    `systemctl restart`, just a green line."""
    fixture = FIXTURE_NO_KEY.replace(
        "  viewer_chat_ids: []\n",
        f"  viewer_chat_ids: []\n  allowed_user_ids: [{OWNER_ID}]\n")
    out = _run(tmp_path, fixture, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == fixture
    assert "install " not in out["calls"]
    assert "systemctl restart" not in out["calls"]
    assert "e deja restrâns" in out["proc"].stdout


def test_candidate_validation_blocks_the_write_before_anything_is_touched(tmp_path):
    """A `sentinel.yaml` edited into something the daemon's own loader
    rejects, and then restarted into, takes down the alerting channel — the
    exact CLAUDE.md mistake, made a different way. `telegram_config_loads_
    with_owner` runs against the CANDIDATE first; when it fails, nothing may
    be written, nothing may restart, and the run must not fail the whole
    install for a check that touched no live file yet."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID,
               python_fails_from_call=1)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == FIXTURE_NO_KEY, "the live file was touched despite a failed candidate check"
    assert "install " not in out["calls"]
    assert "systemctl restart" not in out["calls"]


def test_run_twice_second_run_changes_nothing(tmp_path):
    """The literal falsification the task asks for: run the step, then run it
    again against what it just wrote, and confirm the second pass is inert."""
    out1 = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID)
    assert out1["proc"].returncode == 0, out1["proc"].stderr
    assert "install " in out1["calls"], "first run did not write anything to re-run against"

    out2 = _run(tmp_path, out1["yaml"], stdin_user_id=OWNER_ID)
    assert out2["proc"].returncode == 0, out2["proc"].stderr
    assert out2["yaml"] == out1["yaml"]
    assert "install " not in out2["calls"], "second run wrote again — not idempotent"
    assert "systemctl restart" not in out2["calls"]


def test_no_restart_attempted_when_unit_is_not_installed(tmp_path):
    """A build without sentinel-telegram must not fail this step trying to
    restart a service that was never shipped."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID,
               telegram_unit_present=False)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert f"[{OWNER_ID}]" in out["yaml"], "the file itself must still be written"
    assert "install " in out["calls"]
    assert "systemctl restart" not in out["calls"]


def test_no_restart_attempted_when_unit_is_installed_but_not_running(tmp_path):
    """A host where sentinel-telegram is stopped for some other reason: the
    file must still be written so the value is there the next time it starts,
    but nothing here should try to start a service the operator has not."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID,
               telegram_unit_present=True, telegram_unit_active=False)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert f"[{OWNER_ID}]" in out["yaml"]
    assert "install " in out["calls"]
    assert "systemctl restart" not in out["calls"]


def test_restart_confirms_effect_through_the_daemons_own_loader(tmp_path):
    """The requirement in full: `systemctl restart` returning 0 is not proof.
    This exercises the REAL post-restart check — `telegram_config_loads_with_
    owner` against the file actually on disk, through a real `sentinel.config`
    import in this repo, not a stub — and only a genuinely correct write makes
    it pass."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID,
               telegram_unit_present=True, telegram_unit_active=True,
               is_active_output="active", nrestarts_sequence="4 4 4 4 4",
               restart_rc=0, settle_s=1)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert f"[{OWNER_ID}]" in out["yaml"]
    assert "systemctl restart sentinel-telegram" in out["calls"]
    assert "activ și stabil" in out["proc"].stdout
    assert "verificat prin propriul loader" in out["proc"].stdout


def test_a_crash_loop_after_restart_is_not_reported_as_success(tmp_path):
    """CLAUDE.md's own table, the row about `is-active` checked once: a unit
    that dies and is restarted by systemd passes through `active` on every
    lap. NRestarts climbing DURING the settle window — the observable this
    step actually watches — must abort the install rather than print a green
    line over a bot that is crash-looping on the config just written."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID,
               telegram_unit_present=True, telegram_unit_active=True,
               is_active_output="active", nrestarts_sequence="5 5 9",
               restart_rc=0, settle_s=2)
    assert out["proc"].returncode != 0, "a crash loop must not exit 0"
    assert "se repornește în buclă" in out["proc"].stderr
    assert "activ și stabil" not in out["proc"].stdout


def test_post_restart_reverification_is_load_bearing(tmp_path):
    """The SECOND call to `telegram_config_loads_with_owner` — against the
    file the just-restarted unit was actually started against, after the
    settle window — is not decorative. `install` copies the validated
    candidate byte for byte, so no ordinary fixture can make the two calls
    disagree; this makes them disagree on purpose (the loader stub fails
    starting on its 2nd invocation, which is this exact call) to prove the
    line still runs and its verdict still ends the install."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID,
               telegram_unit_present=True, telegram_unit_active=True,
               is_active_output="active", nrestarts_sequence="1 1",
               restart_rc=0, settle_s=1, python_fails_from_call=2)
    assert out["proc"].returncode != 0, "a disagreeing post-restart check must not exit 0"
    assert "nu se mai încarcă drept" in out["proc"].stderr
    assert "activ și stabil" not in out["proc"].stdout


def test_a_genuinely_block_form_value_is_left_alone(tmp_path):
    """The one shape this step refuses to guess at: `allowed_user_ids:` with
    nothing on its own line, followed by `- id` items. Rewriting it wrong
    would silently narrow (or widen) who may act; refusing and saying so is
    the only safe move. This is the exact case whose detection this file's own
    falsification pass found broken — see the module docstring."""
    fixture = FIXTURE_NO_KEY.replace(
        "  viewer_chat_ids: []\n",
        "  viewer_chat_ids: []\n  allowed_user_ids:\n    - 111111111\n    - 222222222\n")
    out = _run(tmp_path, fixture, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == fixture, "a block-form value was rewritten without understanding it"
    assert "NU o rescrie" in out["proc"].stderr or "mai multe linii" in out["proc"].stderr
    assert "install " not in out["calls"]


def test_block_form_at_the_keys_own_indent_is_recognized(tmp_path):
    """YAML never requires a block sequence to be indented past its parent
    key — `allowed_user_ids:` then `- id` at the SAME indent as the key is
    exactly as valid as two extra spaces of indentation. The first version
    of `telegram_allowed_user_ids_is_block_form` only recognised the
    two-extra-spaces shape, so this one fell through to the line-rewrite
    path: `allowed_user_ids:` got replaced in place and the `- id` lines
    below it were left dangling, invalid YAML — caught only because the
    daemon's own loader refuses to load it, never because this step
    understood what it was looking at."""
    fixture = FIXTURE_NO_KEY.replace(
        "  viewer_chat_ids: []\n",
        "  viewer_chat_ids: []\n  allowed_user_ids:\n  - 111111111\n  - 222222222\n")
    out = _run(tmp_path, fixture, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == fixture, "a same-indent block-form value was rewritten without understanding it"
    assert "mai multe linii" in out["proc"].stderr
    assert "install " not in out["calls"]


def test_block_form_with_a_comment_before_the_first_item_is_recognized(tmp_path):
    """A comment line between `allowed_user_ids:` and its first `- id` item
    is legal YAML and does not end the key's block — mistaking it for "no
    items follow" is the same defect as the same-indent case above, reached
    a different way: the key gets rewritten in place and the real items are
    left dangling below it."""
    fixture = FIXTURE_NO_KEY.replace(
        "  viewer_chat_ids: []\n",
        "  viewer_chat_ids: []\n  allowed_user_ids:\n"
        "    # former operator, kept for reference\n    - 111111111\n")
    out = _run(tmp_path, fixture, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == fixture, (
        "a block-form value with a leading comment was rewritten without understanding it")
    assert "mai multe linii" in out["proc"].stderr
    assert "install " not in out["calls"]


def test_loader_unreachable_is_a_clean_noop_not_silent(tmp_path):
    """`telegram_config_loads_with_owner`'s own rc=2 path: the venv or
    `sentinel.config` cannot be reached from here for a reason that has
    nothing to do with PYTHONPATH (a broken venv, a missing dependency).
    The file must not move, `install` must never run, the run must still
    exit 0 (a check that never got to ask is not proof the write is wrong),
    and — the F2 half of this — the operator has to be told at the END of
    the run, not just in a warn buried mid-install."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID,
               python_import_broken=True)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert out["yaml"] == FIXTURE_NO_KEY, "the live file was touched despite an unreachable loader"
    assert "install " not in out["calls"]
    assert "nu pot verifica" in out["proc"].stderr
    assert "CLOSING_NOTE:" in out["calls"], "loader-unreachable must still end with a closing note"


def test_trailing_blank_line_survives_byte_exact(tmp_path):
    """Both `$(cat …)` and the rewrite's own output travel through bash
    command substitution on their way into this step, which strips EVERY
    trailing newline, not just one. The live prod sentinel.yaml ends
    `…\\n\\n` — content, then a real trailing blank line, then EOF — and a
    naive `printf '%s\\n' "$desired"` at write time silently turns that into
    a single trailing newline, deleting a byte nobody asked to delete. This
    fixture reproduces that exact shape (not on either live host's telegram:
    block itself, but as a structural probe of the read/write path) and
    checks the output byte for byte, not just its content."""
    fixture = FIXTURE_NO_KEY + "\n"  # file now ends "\n\n", not "\n"
    assert fixture.endswith("\n\n")
    out = _run(tmp_path, fixture, stdin_user_id=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    expected = fixture.replace(
        "  require_pin_for_apply: false\n\n",
        f"  require_pin_for_apply: false\n  allowed_user_ids: [{OWNER_ID}]\n\n")
    assert out["target"].read_bytes() == expected.encode("utf-8"), (
        "trailing bytes were not preserved exactly")


def test_never_writes_under_a_different_top_level_key(tmp_path):
    """`allowed_user_ids:` under some OTHER top-level section, at the SAME
    indent telegram: uses, and appearing BEFORE telegram: in the file, must
    never be touched — only the key inside `telegram:` is this step's
    business. Falsified directly: dropping the `in_tg &&` guard in
    `telegram_allowed_user_ids_rewrite` (:6316) makes the awk script match
    the FIRST line at the right indent starting with `allowed_user_ids:`
    anywhere in the file — here the foreign one, which comes first — so the
    foreign key gets overwritten with the new owner id and telegram's own
    (real) key is left at its stale value. Neither half of that is
    survivable: a foreign key silently changed, and the actual allowlist
    left wrong.

    Goes at `telegram_allowed_user_ids_rewrite` directly (see `_rewrite`),
    not through `step_telegram_owner` end to end: no real top-level section
    in `sentinel.yaml`'s schema is named `allowed_user_ids`-bearing except
    `telegram` itself, so any fixture shaped to probe a FOREIGN key at that
    name would be refused by `sentinel.config.load_config` as an unknown
    key, for a reason that has nothing to do with the guard this test
    exists to check, and the real defect would be masked by that unrelated
    rejection."""
    fixture = ("other:\n  allowed_user_ids: [999999999]\n\ntelegram:\n"
               "  enabled: true\n  allowed_user_ids: [111111111]\n")
    out = _rewrite(tmp_path, fixture, f"[{OWNER_ID}]")
    lines = out.splitlines()
    assert "  allowed_user_ids: [999999999]" in lines, "the foreign key under other: was touched"
    assert f"  allowed_user_ids: [{OWNER_ID}]" in lines, "telegram's own key was not written"


def test_secret_from_stdin_is_used_even_when_disk_disagrees(tmp_path):
    """Read-stdin-first, disk-second: a value on stdin must win over a stale
    one already on disk, the same precedence step 27 itself uses."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=OWNER_ID,
               on_disk_secret="111111111")
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert f"[{OWNER_ID}]" in out["yaml"]


def test_secret_falls_back_to_disk_when_stdin_is_empty(tmp_path):
    """The case a normal re-deploy is in: step 27 already persisted the key on
    an earlier run and this run supplies nothing new on stdin. The step must
    still find it."""
    out = _run(tmp_path, FIXTURE_NO_KEY, stdin_user_id=None, on_disk_secret=OWNER_ID)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert f"[{OWNER_ID}]" in out["yaml"]


def test_is_always_step(tmp_path):
    """`telegram_owner` has to be in ALWAYS_STEPS: whether the group is still
    the only thing on the allowlist is a fact about the RUNNING host, not a
    deed done once — see the comment beside ALWAYS_STEPS for the full
    reasoning this mirrors from `journal_storage`."""
    script = tmp_path / "check.sh"
    script.write_text("source ./lib/common.sh\n"
                       'step_is_always telegram_owner && echo YES || echo NO\n',
                       encoding="utf-8", newline="\n")
    proc = subprocess.run([BASH, str(script).replace("\\", "/")],
                          cwd=REPO / "deploy", capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          env={**os.environ, "NO_COLOR": "1"})
    assert proc.stdout.strip() == "YES", proc.stdout + proc.stderr


def test_operator_secret_keys_carries_the_new_key():
    """Half 1 of the fix: a value the operator puts on stdin must not be
    silently dropped by step_secrets for lacking a place on this list — the
    exact failure `--force-step 22,27` produced for the beacon key."""
    match = re.search(r"OPERATOR_SECRET_KEYS=\((.*?)\)", INSTALL_TEXT, re.S)
    assert match, "OPERATOR_SECRET_KEYS not found"
    assert "TELEGRAM_OWNER_USER_ID" in match.group(1)


# ---------------------------------------------------------------------------
# Every refusal branch prints a closing_note — one witness test per branch
# ---------------------------------------------------------------------------
#
# `step_telegram_owner` has ten places that decide NOT to touch
# allowed_user_ids and return 0 anyway, plus one success path that also
# closes with a note. Before this test, only four of the ten refusal
# branches had a test that would notice `closing_note` vanishing from them —
# the other six could be deleted outright and the existing suite (46 tests
# across this file and test_secrets_preserved.py — 25 + 21 — at the time
# this was written) would stay green. That gap is exactly how the operator ends up
# looking at "Instalare completă" after a run that silently left a GROUP in
# command of the bot: the warn on stderr is real, but nothing puts it in the
# end-of-run summary a person actually reads.
#
# `TOTAL_CLOSING_NOTE_CALLS` ties this list to the source instead of to
# memory: it counts every `closing_note(` call textually present in the step
# 42 block (ten refusals + one success == 11), so a branch added later
# without updating CASES below fails this file's own count assertion before
# it ever gets to running anything — the silent-empty-list failure mode
# CLAUDE.md warns about, closed by deriving the expected size from the code
# rather than typing "10" twice and hoping they stay in sync.
#
# `'closing_note "'`, not `'closing_note('`: every call site in install.sh is
# a bash command (`closing_note "message"`), never a function call with
# parens — parens appear only in the `closing_note() { … }` definition
# itself, which lives outside the step 42 block `_step42_source()` returns
# and so is never counted here regardless.
TOTAL_CLOSING_NOTE_CALLS = _step42_source().count('closing_note "')

REFUSAL_BLOCK_FORM_FIXTURE = FIXTURE_NO_KEY.replace(
    "  viewer_chat_ids: []\n",
    "  viewer_chat_ids: []\n  allowed_user_ids:\n    - 111111111\n    - 222222222\n")

REFUSAL_CASES = [
    pytest.param(
        dict(fixture=FIXTURE_NO_KEY, stdin_user_id=None),
        "TELEGRAM_OWNER_USER_ID lipsă din secrets",
        id="secret_absent",
    ),
    pytest.param(
        dict(fixture=FIXTURE_NO_KEY, stdin_user_id="not-a-number"),
        "nu arată ca un id numeric",
        id="non_numeric",
    ),
    pytest.param(
        dict(fixture=None, stdin_user_id=OWNER_ID),
        "nu există încă",
        id="target_missing",
    ),
    pytest.param(
        dict(fixture="web:\n  domain: null\n", stdin_user_id=OWNER_ID),
        "nu are structura 'telegram: / enabled:' așteptată",
        id="no_telegram_enabled_structure",
    ),
    pytest.param(
        dict(fixture=REFUSAL_BLOCK_FORM_FIXTURE, stdin_user_id=OWNER_ID),
        "pasul 42 nu îl rescrie",
        id="block_form",
    ),
    pytest.param(
        dict(fixture=FIXTURE_NO_KEY, stdin_user_id=OWNER_ID, cat_fails_on_target=True),
        "nu a putut fi citit",
        id="unreadable",
    ),
    pytest.param(
        dict(fixture=FIXTURE_NO_KEY, stdin_user_id=OWNER_ID, rewrite_stub="fails"),
        "rescrierea a eșuat",
        id="rewrite_failed",
    ),
    pytest.param(
        dict(fixture=FIXTURE_NO_KEY, stdin_user_id=OWNER_ID, rewrite_stub="empty"),
        "rescrierea a produs un fișier gol",
        id="rewrite_empty",
    ),
    pytest.param(
        dict(fixture=FIXTURE_NO_KEY, stdin_user_id=OWNER_ID, python_import_broken=True),
        "loaderul Sentinel nu a putut fi atins",
        id="loader_unreachable_rc2",
    ),
    pytest.param(
        dict(fixture=FIXTURE_NO_KEY, stdin_user_id=OWNER_ID, python_fails_from_call=1),
        "candidatul respins de loaderul Sentinel",
        id="candidate_rejected",
    ),
]


def test_refusal_case_list_matches_the_source():
    """Falsifies the falsifier: if `CASES` below were ever emptied, trimmed,
    or left out of sync with a branch added to (or removed from)
    `step_telegram_owner`, this is what would notice — a parametrised list
    that quietly came out short is the exact failure mode CLAUDE.md names,
    and a `len(REFUSAL_CASES) == 10` alone would not catch a NEW eleventh
    refusal branch shipped without also updating this file. Comparing
    against a count read from install.sh itself does."""
    assert len(REFUSAL_CASES) == 10
    assert TOTAL_CLOSING_NOTE_CALLS == len(REFUSAL_CASES) + 1, (
        f"step 42 now calls closing_note() {TOTAL_CLOSING_NOTE_CALLS} times "
        f"(10 refusals + 1 success expected) but REFUSAL_CASES has "
        f"{len(REFUSAL_CASES)} entries — a branch was added or removed "
        "without this parametrisation being updated")


@pytest.mark.parametrize("run_kwargs,marker", REFUSAL_CASES)
def test_every_refusal_branch_closes_with_exactly_one_note(tmp_path, run_kwargs, marker):
    """Each of the ten paths where `step_telegram_owner` declines to touch
    allowed_user_ids and returns 0 has to leave the operator a note in the
    end-of-run summary, not just a `warn` on stderr — CLAUDE.md's own
    complaint about this step is that a green "Instalare completă" banner
    can print over exactly this kind of silent refusal.

    Two things checked together, not separately, because either one alone
    passes for the wrong reason:
      - exactly ONE `CLOSING_NOTE:` line — a branch that fires the note
        twice (e.g. falling through into a second refusal) is as wrong as
        one that fires it zero times, and a bare "note present somewhere"
        check would miss a duplicate;
      - the note's own text names THIS branch, not merely a `CLOSING_NOTE:`
        prefix — a test that only grepped for the prefix would stay green
        if the wrong branch fired (say, the digit guard catching a case
        meant to reach the loader), because SOME note would still appear.
    """
    out = _run(tmp_path, **run_kwargs)
    assert out["proc"].returncode == 0, out["proc"].stderr
    notes = [line for line in out["calls"].splitlines() if line.startswith("CLOSING_NOTE:")]
    assert len(notes) == 1, (
        f"expected exactly one CLOSING_NOTE:, got {len(notes)}: {notes}")
    assert marker in notes[0], (
        f"closing note did not name this branch — got: {notes[0]!r}")
