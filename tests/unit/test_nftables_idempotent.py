"""Step 29 doubled every rule on the second run over the same table.

`nft -f sentinel-table.nft` does not replace `table inet sentinel` when it
already exists — it ADDS to it. Declaring a set again is a no-op (its elements
survive, which is what a re-run needs for the allowlist and for a live block),
but declaring a CHAIN again appends every rule in the file on top of whatever
was already there. Measured on both production hosts on 2026-09-07 after step
29 ran a second time over the same table: `nft list chain inet sentinel input`
showed 12 `saddr` rules where the file defines 6, the second copy sitting at
`counter packets 0`; `forward` the same. Accept/drop decisions did not change
— the first matching terminal rule still wins — but the non-terminating
`counter` rule on the watchlist counts every packet once per copy, so a hit
count read back is a multiple of the truth; the ruleset grows without bound on
every further re-run (`--force-step 29`, a reset state marker, a second host
touched the same day); and `nft list`, which is what an operator reads when
checking the host, no longer matches `deploy/nftables/sentinel-table.nft`.

Every test below names the operator-visible failure it prevents. Falsified by
reintroducing the removed defect (unconditional `nft -f`, one flushed chain
instead of two, the load run before the flush, the readback check deleted) and
confirming the test goes red before restoring the fix.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "deploy" / "install.sh"
TABLE_NFT = REPO / "deploy" / "nftables" / "sentinel-table.nft"

BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="no bash on PATH")


def _env(**extra: str) -> dict[str, str]:
    import os
    return {**os.environ, "NO_COLOR": "1", **extra}


def run_bash(script: str, **env: str) -> subprocess.CompletedProcess:
    """Run a script on stdin, from the repo root — see test_allowlist_v6.py
    for why: argv quoting mangles a script this size on Windows, and an
    absolute path reaches MSYS bash as relative under a directory called C:."""
    return subprocess.run(
        [BASH], input=script, cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=_env(**env),
    )


def _install_function(name: str) -> str:
    """One function lifted verbatim out of the shipped deploy/install.sh.

    Cut from the file, never retyped — a test carrying its own copy of the
    logic passes while the shipped code is broken.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\(\) \{{.*?^\}}", text, re.S | re.M)
    assert match, f"{name}() not found in install.sh"
    return match.group(0)


# ---------------------------------------------------------------------------
# Harness for step_nftables — nftables idempotency only.
# ---------------------------------------------------------------------------
# No real nft on this machine, and none is needed: what is under test is
# WHICH ORDER the shipped step hands commands to nft, and what it does with
# what nft reports back. So nft is a shell function that logs its argv (and,
# for `-f`/`-c -f`, the exact content of the file it was handed, one
# `loaded| `/`checked| ` line per line of the file — so the ORDER inside the
# generated transaction file is checkable, not just that a command ran).
#
# Knobs:
#   NFT_TABLE_EXISTS      `nft list table inet sentinel` succeeds.
#   NFT_FLUSH_FAILS       the `-f` load fails IF the file it was handed
#                         contains a `flush chain` line — i.e. the kernel
#                         rejects the flush-plus-reload transaction.
#   NFT_CHAIN_INPUT_COUNT / NFT_CHAIN_FORWARD_COUNT
#                         total number of `@` rule lines `nft list chain inet
#                         sentinel <input|forward>` answers with, shaped like
#                         the real chain content (a multiple of 6 — one real
#                         chain's worth of rules, repeated). Defaults to 6
#                         (correct, one copy).
#   NFT_CHAIN_LIST_FAILS  the chain readback fails outright.
#   NFT_SCRIPT_DIR        overrides SCRIPT_DIR, so step_nftables looks for
#                         sentinel-table.nft somewhere other than the real
#                         deploy/nftables/ — used to exercise the missing-file
#                         path without touching the shipped file.
HARNESS = r"""
set -euo pipefail
source deploy/lib/common.sh

work="$(mktemp -d)"
# Overridable so one test can point step_nftables at a directory with no
# nftables/sentinel-table.nft in it (F3: the missing-file path), without
# disturbing every other test, which needs the real shipped file.
SCRIPT_DIR="${NFT_SCRIPT_DIR:-deploy}"
SENTINEL_PREFIX="${work}/opt"
SENTINEL_CONFIG_DIR="${work}/etc"
mkdir -p "$SENTINEL_CONFIG_DIR"

NFT_LOG="${work}/nft.log"
: > "$NFT_LOG"

nft() {
    printf '%s\n' "$*" >> "$NFT_LOG"
    case "${1:-}" in
        list)
            case "${2:-}" in
                table)
                    # Answers "exists" only for the exact table this step is
                    # supposed to ask about — a typo'd family or table name in
                    # install.sh (`inet sentinelx`, `ip sentinel`) must read as
                    # "table not found", not fall through to NFT_TABLE_EXISTS
                    # regardless of what was actually asked. Getting this
                    # wrong would mean the whole flush-before-reload path is
                    # covered by nothing: the existence check could point at
                    # the wrong table and every test here would still pass.
                    if [[ "${3:-}" == "inet" && "${4:-}" == "sentinel" \
                          && -n "${NFT_TABLE_EXISTS:-}" ]]; then
                        printf 'table inet sentinel {\n}\n'
                        return 0
                    fi
                    printf 'Error: No such file or directory\n' >&2
                    return 1
                    ;;
                chain)
                    if [[ -n "${NFT_CHAIN_LIST_FAILS:-}" ]]; then
                        printf 'Error: No such file or directory\n' >&2
                        return 1
                    fi
                    # Shaped after the REAL `nft list chain inet sentinel
                    # <input|forward>` output captured on production on
                    # 2026-09-07, not a stand-in single line — `forward`'s
                    # blocklist rules match on both `saddr` and `daddr` (see
                    # sentinel-table.nft), so a stub built only out of `saddr`
                    # lines would never distinguish `grep -c '@'` (correct,
                    # counts every match) from `grep -c 'saddr @'` (undercounts
                    # forward by exactly its 2 `daddr` lines, and would warn
                    # "may have doubled" on every correct install).
                    #
                    # NFT_CHAIN_*_COUNT is the TOTAL number of `@` lines to
                    # answer with, i.e. what step_nftables' readback is meant
                    # to count. 6 (the default) is one real chain's worth of
                    # rules; a multiple of 6 simulates a chain doubled (or
                    # tripled) by a re-run that skipped the flush, and a
                    # count BELOW 6 simulates rules actually missing from a
                    # live table (a partial or truncated load) — cycled out
                    # of the same 6 real lines rather than a distinct fake
                    # case, so the shape stays realistic either way.
                    local chain_name="${5:-}" count i
                    if [[ "$chain_name" == "input" ]]; then
                        count="${NFT_CHAIN_INPUT_COUNT:-6}"
                    else
                        count="${NFT_CHAIN_FORWARD_COUNT:-6}"
                    fi
                    local -a rule_lines
                    if [[ "$chain_name" == "input" ]]; then
                        rule_lines=(
                            'ip saddr @allowlist_v4 accept'
                            'ip6 saddr @allowlist_v6 accept'
                            'ip saddr @watchlist_v4 counter packets 0 bytes 0'
                            'ip6 saddr @watchlist_v6 counter packets 0 bytes 0'
                            'ip saddr @blocklist_v4 counter packets 84085 bytes 5044932 drop'
                            'ip6 saddr @blocklist_v6 counter packets 0 bytes 0 drop'
                        )
                    else
                        rule_lines=(
                            'ip saddr @allowlist_v4 accept'
                            'ip6 saddr @allowlist_v6 accept'
                            'ip saddr @blocklist_v4 counter packets 0 bytes 0 drop'
                            'ip daddr @blocklist_v4 counter packets 0 bytes 0 drop'
                            'ip6 saddr @blocklist_v6 counter packets 0 bytes 0 drop'
                            'ip6 daddr @blocklist_v6 counter packets 0 bytes 0 drop'
                        )
                    fi
                    printf 'table inet sentinel {\n\tchain %s {\n' "$chain_name"
                    if [[ "$chain_name" == "input" ]]; then
                        printf '\t\ttype filter hook input priority filter - 5; policy accept;\n'
                        printf '\t\tct state established,related accept\n'
                        printf '\t\tiif "lo" accept\n'
                    else
                        printf '\t\ttype filter hook forward priority filter - 5; policy accept;\n'
                        printf '\t\tct state established,related accept\n'
                    fi
                    for ((i = 0; i < count; i++)); do
                        printf '\t\t%s\n' "${rule_lines[i % 6]}"
                    done
                    printf '\t}\n}\n'
                    return 0
                    ;;
                set)
                    if [[ -n "${NFT_LIST_FAILS:-}" ]]; then
                        printf 'Error: No such file or directory\n' >&2
                        return 1
                    fi
                    printf 'table inet sentinel {\n    set %s {\n    }\n}\n' "${5:-?}"
                    return 0
                    ;;
            esac
            ;;
        -c)
            if [[ "${2:-}" == "-f" && -f "${3:-}" ]]; then
                while IFS= read -r __l; do
                    printf 'checked| %s\n' "$__l" >> "$NFT_LOG"
                done < "${3}"
            fi
            if [[ -n "${NFT_CHECK_FAILS:-}" ]]; then
                printf '%s\n' "${NFT_CHECK_ERR:-Error: syntax error, unexpected string}" >&2
                return 1
            fi
            return 0
            ;;
        -f)
            local f="${2:-}"
            if [[ -f "$f" ]]; then
                while IFS= read -r __l; do
                    printf 'loaded| %s\n' "$__l" >> "$NFT_LOG"
                done < "$f"
            fi
            if [[ -n "${NFT_FLUSH_FAILS:-}" ]] && grep -q '^flush chain' "$f" 2>/dev/null; then
                printf '%s\n' "${NFT_FLUSH_ERR:-Error: Could not process rule: Device or resource busy}" >&2
                return 1
            fi
            return 0
            ;;
        add)
            local elem="${6:-}" pat
            elem="${elem#\{ }"; elem="${elem% \}}"
            for pat in ${NFT_ADD_FAILS:-}; do
                if [[ "$elem" == "$pat" ]]; then
                    printf '%s\n' "${NFT_ADD_ERR:-Error: Could not resolve hostname}" >&2
                    return 1
                fi
            done
            ;;
    esac
    return 0
}

public_ips() { :; }
getent() { return 0; }

install() {
    local args=("$@")
    if [[ "${1:-}" == "-d" ]]; then
        mkdir -p "${args[${#args[@]}-1]}"
    else
        mkdir -p "$(dirname "${args[${#args[@]}-1]}")"
        cp "${args[${#args[@]}-2]}" "${args[${#args[@]}-1]}"
    fi
}
chown() { :; }
chmod() { :; }

__FUNCTIONS__

STEP_RC=0
( step_nftables ) > "${work}/step.out" || STEP_RC=$?

printf '===NFT===\n';    cat "$NFT_LOG"
printf '===STDOUT===\n'; cat "${work}/step.out"
printf '===RC===\n%s\n' "$STEP_RC"
rm -rf "$work"
"""


class StepResult:
    def __init__(self, proc: subprocess.CompletedProcess) -> None:
        self.proc = proc
        self.stderr = proc.stderr
        body = proc.stdout
        self.nft = _section(body, "NFT")
        self.stdout = _section(body, "STDOUT")
        self.rc = int(_section(body, "RC").strip())

    @property
    def loaded_lines(self) -> list[str]:
        """Every line handed to nft via `-f`, across every call, in order —
        the CONTENT of the transaction file(s), not just that `-f` ran."""
        return [l[len("loaded| "):] for l in self.nft.splitlines()
                if l.startswith("loaded| ")]

    @property
    def added(self) -> list[str]:
        out = []
        for line in self.nft.splitlines():
            match = re.match(r"add element inet sentinel (\S+) \{ (\S+) \}$", line.strip())
            if match:
                out.append(f"{match.group(1)} {match.group(2)}")
        return out


def _section(body: str, name: str) -> str:
    marker = f"==={name}===\n"
    assert marker in body, f"the harness printed no {name} section:\n{body}"
    rest = body.split(marker, 1)[1]
    return re.split(r"^===\w+===$", rest, maxsplit=1, flags=re.M)[0]


def run_step(_expect_rc: int = 0, **env: str) -> StepResult:
    functions = "\n".join(
        _install_function(name)
        for name in ("extra_allowlist_entries", "allowlist_collect",
                     "nft_allowlist_add", "step_nftables")
    )
    script = HARNESS.replace("__FUNCTIONS__", functions)
    proc = run_bash(script, **env)
    assert proc.returncode == 0, f"the harness itself failed:\n{proc.stdout}\n{proc.stderr}"
    result = StepResult(proc)
    assert result.rc == _expect_rc, (
        f"step_nftables exited {result.rc}, expected {_expect_rc}:\n"
        f"{result.stdout}\n{proc.stderr}")
    return result


# ---------------------------------------------------------------------------
# The re-run that doubles the ruleset
# ---------------------------------------------------------------------------
def test_an_existing_table_is_flushed_before_the_reload():
    """"regulile din lanțuri se dublează la fiecare rulare a pasului 29 peste
    tabela existentă, contoarele de watchlist numără de două ori și `nft list`
    nu mai seamănă cu fișierul".

    On a table that already exists, `nft -f` on the shipped file APPENDS every
    rule rather than replacing them. The fix is to flush both chains' rules
    inside the SAME transaction that reloads the table, so the chain ends up
    with exactly one copy. This asserts the order inside that transaction:
    both flushes appear, and both appear before the table (and therefore its
    chain rules) is declared.
    """
    res = run_step(NFT_TABLE_EXISTS="1")
    lines = res.loaded_lines
    assert lines, f"nothing was ever loaded via `nft -f`:\n{res.nft}"

    idx_flush_input = next((i for i, l in enumerate(lines)
                            if l.strip() == "flush chain inet sentinel input"), None)
    idx_flush_forward = next((i for i, l in enumerate(lines)
                              if l.strip() == "flush chain inet sentinel forward"), None)
    idx_table = next((i for i, l in enumerate(lines)
                      if l.strip().startswith("table inet sentinel {")), None)

    assert idx_flush_input is not None, f"input chain never flushed:\n{lines}"
    assert idx_flush_forward is not None, f"forward chain never flushed:\n{lines}"
    assert idx_table is not None, f"the table definition was never loaded:\n{lines}"
    assert idx_flush_input < idx_table, "input flushed AFTER the reload — rules would double"
    assert idx_flush_forward < idx_table, "forward flushed AFTER the reload — rules would double"


def test_a_missing_table_is_loaded_with_no_flush_at_all():
    """First install: there is no `inet sentinel` table yet. `flush chain` on a
    table that does not exist is a kernel error — attempting one here would
    turn a clean first install into a failed one for no reason. This is also
    the existing-behaviour guarantee: nothing about a fresh host may change.
    """
    res = run_step()  # NFT_TABLE_EXISTS unset -> `nft list table` fails
    assert "flush chain" not in res.nft, res.nft
    assert any(l.strip().startswith("table inet sentinel {")
               for l in res.loaded_lines), res.loaded_lines


def test_a_rejected_flush_and_reload_leaves_the_running_table_unchanged():
    """The flush and the reload are one `nft -f` transaction. If the kernel
    rejects it — a future nft, a locked table, a concurrent change — nothing
    may have been committed: an operator reading `nft -f` failed must not then
    find a live table with 18 copies of every rule because the step tried to
    "carry on" past a refusal it could not undo.

    So the step DIES here rather than proceeding to any further step (which
    would include re-adding allowlist elements against a table state nobody
    can vouch for): no `add element` call is made at all.
    """
    res = run_step(_expect_rc=1, NFT_TABLE_EXISTS="1", NFT_FLUSH_FAILS="1")
    assert "UNCHANGED" in res.stderr, res.stderr
    assert res.added == [], f"the step proceeded to add elements after a rejected reload:\n{res.nft}"


def test_a_missing_table_file_dies_by_name_and_leaves_no_scratch_file(tmp_path):
    """The flush+reload file is built by `{ echo ...; echo ...; cat
    "$table_file"; } > "$load_file"`. If `$table_file` — the shipped
    sentinel-table.nft — is missing or unreadable (a broken deploy, a
    permissions slip, `--force-step 29` run from the wrong directory), `cat`
    is the last command in that group, and its failure was not checked.

    What that costs depends on who calls the step, and the two callers
    differ. In production the chain is `main` -> `run_step` -> a bare `"$@"`,
    so errexit is LIVE: the unchecked `cat` aborted the whole install with
    nothing but cat's own line on stderr — no `[FATAL]`, no step name — and
    left the `mktemp` scratch file in /tmp. The running table was untouched.
    In this harness the step runs as `( step_nftables ) || STEP_RC=$?`, and
    bash disables errexit inside a compound command whose status is tested
    by `||`; there the unchecked `cat` did NOT stop anything, `$load_file`
    held only the two `flush chain` lines, `nft -f` accepted that truncated
    transaction, and the step logged its usual success — which is the shape
    an operator would see from any caller that wraps the step in `if`, `||`
    or `$( )`. Verified on 2026-09-07 by running both shapes.

    Guarding the `cat` explicitly with `if ! { ... }; then die ...; fi` does
    not rely on errexit at all, so both callers get the same named failure.
    This asserts three separate facts about it, because any one alone can
    pass while the other two still lie: the step exits nonzero and names the
    file that could not be read, `nft -f` is never invoked with the truncated
    transaction, and nothing is left behind on disk for every broken deploy
    to accumulate.
    """
    missing = tmp_path / "no-table-here"
    missing.mkdir()
    scratch = tmp_path / "scratch-tmpdir"
    scratch.mkdir()

    res = run_step(_expect_rc=1, NFT_TABLE_EXISTS="1",
                    NFT_SCRIPT_DIR=str(missing), TMPDIR=str(scratch))

    assert "[FATAL]" in res.stderr, res.stderr
    assert "sentinel-table.nft" in res.stderr, res.stderr
    assert res.loaded_lines == [], (
        f"nft -f ran on a table file that was never successfully assembled:\n{res.nft}")
    leftover = list(scratch.iterdir())
    assert leftover == [], (
        f"the mktemp scratch file for the flush+reload transaction was left behind: {leftover}")


# ---------------------------------------------------------------------------
# The read-back that catches a doubling this design did not prevent
# ---------------------------------------------------------------------------
def test_a_doubled_chain_is_warned_about_by_number():
    """Even with the flush in place, a check that only confirms the flush RAN
    would be exactly the "confirmed intent, not effect" mistake this
    repository keeps shipping — a future refactor, a flag typo, a kernel that
    silently ignores an unrecognised `flush chain` line, and the ruleset could
    double again with every prior gate reporting green.

    So the live rule count is read back and compared against what the shipped
    file defines. A mismatch has to name BOTH numbers — the one on the host
    and the one in the file — because an operator deciding whether to worry
    needs to see the size of the drift, not just that there is one.

    A count ABOVE the expected is the safe direction — nothing extra is
    dropped, decisions stay right, only hit counts and `nft list` history are
    wrong — and the wording has to say so: "DUPLICATED", not the same
    ambiguous phrase used for a count that means something is now unprotected.
    """
    res = run_step(NFT_TABLE_EXISTS="1",
                    NFT_CHAIN_INPUT_COUNT="12", NFT_CHAIN_FORWARD_COUNT="12")
    assert "12" in res.stderr and "6" in res.stderr, res.stderr
    assert "input" in res.stderr, res.stderr
    assert "forward" in res.stderr, res.stderr
    assert "DUPLICATED" in res.stderr, res.stderr
    assert "MISSING" not in res.stderr, res.stderr


def test_a_chain_missing_rules_is_warned_about_as_a_protection_gap():
    """The opposite mismatch is the dangerous one: fewer rules than the file
    defines means a blocklist or watchlist rule is not actually loaded, and
    an address Sentinel believes it is blocking is not being dropped — a
    silent, complete failure of what this table exists to do. Reusing the
    same "may have doubled" wording for this case would tell the operator the
    wrong story about which direction the drift went and, on this one, that
    is the story that matters: nothing here is safe to shrug off until the
    next login like a hit-count discrepancy is.
    """
    res = run_step(NFT_TABLE_EXISTS="1",
                    NFT_CHAIN_INPUT_COUNT="4", NFT_CHAIN_FORWARD_COUNT="4")
    assert "4" in res.stderr and "6" in res.stderr, res.stderr
    assert "input" in res.stderr, res.stderr
    assert "forward" in res.stderr, res.stderr
    assert "MISSING" in res.stderr, res.stderr
    assert "DUPLICATED" not in res.stderr, res.stderr


def test_a_correctly_sized_chain_is_reported_ok_not_warned():
    """A warning that fires on every correct install is a warning the operator
    stops reading — which is how the next real doubling goes unnoticed. The
    matching case must be silent on stderr and say `ok` on stdout.
    """
    res = run_step(NFT_TABLE_EXISTS="1",
                    NFT_CHAIN_INPUT_COUNT="6", NFT_CHAIN_FORWARD_COUNT="6")
    assert res.stderr.strip() == "", res.stderr
    assert re.search(r"chain input: 6 rules", res.stdout), res.stdout
    assert re.search(r"chain forward: 6 rules", res.stdout), res.stdout


def test_the_forward_readback_counts_daddr_rules_not_just_saddr():
    """`forward`'s blocklist rules match on BOTH `saddr` and `daddr` — the
    daddr side is what stops a compromised container reaching a blocked
    address outbound, per sentinel-table.nft's own comment. A readback that
    counted only `saddr` lines would see 4 of `forward`'s 6 correct rules and
    warn "may have doubled" — or with the wording split by F4, "rules are
    MISSING" — on EVERY correct install, which is precisely the warning an
    operator learns to stop reading, so the real doubling goes unnoticed when
    it happens. The readback counts `@` occurrences for exactly this reason;
    this test is what would go red if that were narrowed to `saddr @`.
    """
    res = run_step(NFT_TABLE_EXISTS="1")
    assert res.stderr.strip() == "", res.stderr
    assert re.search(r"chain forward: 6 rules", res.stdout), res.stdout


def test_an_unreadable_chain_is_unknown_not_silently_ok():
    """"I could not read the chain" and "the chain is correct" are different
    facts. Collapsing them is how a monitoring tool lies — an operator reading
    a clean run would believe the doubling check had actually run.
    """
    res = run_step(NFT_TABLE_EXISTS="1", NFT_CHAIN_LIST_FAILS="1")
    assert "UNKNOWN" in res.stderr, res.stderr
    assert "input" in res.stderr or "forward" in res.stderr, res.stderr


# ---------------------------------------------------------------------------
# The file and the check cannot drift apart silently
# ---------------------------------------------------------------------------
def test_the_shipped_file_has_exactly_the_rule_count_the_readback_expects():
    """step_nftables hardcodes 6 rules per chain as the correct count — reading
    it out of the file at runtime was rejected as fragile (a comment line
    containing '@' would misparse). Hardcoding it separately from the file
    only holds if something enforces that the two cannot drift apart: an
    editor of the .nft file who adds or removes a rule without touching
    install.sh would otherwise get every readback silently `ok` against the
    WRONG number, forever.
    """
    text = TABLE_NFT.read_text(encoding="utf-8")

    def chain_body(name: str) -> str:
        m = re.search(rf"chain {name} \{{(.*?)\n    \}}", text, re.S)
        assert m, f"chain {name} not found in {TABLE_NFT}"
        return m.group(1)

    input_rules = len(re.findall(r"@\w", chain_body("input")))
    forward_rules = len(re.findall(r"@\w", chain_body("forward")))

    body = _install_function("step_nftables")
    match = re.search(
        r"local -A nft_expected_rules=\(\s*\[input\]=(\d+)\s+\[forward\]=(\d+)\s*\)", body)
    assert match, "step_nftables no longer pins nft_expected_rules the expected way"
    assert int(match.group(1)) == input_rules, (
        f"install.sh expects {match.group(1)} input rules but the file has {input_rules}")
    assert int(match.group(2)) == forward_rules, (
        f"install.sh expects {match.group(2)} forward rules but the file has {forward_rules}")

    # Pinned to a concrete number too, not just "the two files agree" — two
    # files can drift together if both are edited by the same mistake, and
    # this is the number a change to either one has to consciously cross.
    assert input_rules == 6, input_rules
    assert forward_rules == 6, forward_rules


# ---------------------------------------------------------------------------
# The set-only story is unaffected
# ---------------------------------------------------------------------------
def test_a_re_run_still_ends_with_the_allowlist_sets_present():
    """The repair must not turn into a `delete table`: allowlist entries and
    live blocks are held by the SETS, not the chains, and this change never
    flushes or deletes a set. A re-run over an existing table must still
    finish the step and re-populate the allowlist (elements the kernel already
    holds simply come back EEXIST, counted as accepted).
    """
    res = run_step(NFT_TABLE_EXISTS="1")
    assert res.rc == 0
    assert any(l.startswith("list set inet sentinel allowlist_v4") for l in res.nft.splitlines())
    assert any(l.startswith("list set inet sentinel allowlist_v6") for l in res.nft.splitlines())
