"""The allowlist has two sets and only one of them was ever filled.

`deploy/nftables/sentinel-table.nft` declares `allowlist_v4` and `allowlist_v6`
and both base chains accept from both. Nothing ever wrote to `allowlist_v6`:
`step_nftables` appended "/32" to every address it had collected — the admin
address, `response.extra_allowlist`, the host's own addresses, the resolved
Telegram and Anthropic addresses — and pushed the lot at `allowlist_v4` under
`nft add element … 2>/dev/null || true`. The kernel refuses an ipv6_addr in an
ipv4_addr set; the refusal went to /dev/null; the run printed a count that
included it.

On one production host every SSH login arrives over IPv6. `allowlist_v6` was
empty there, so `auto_block` has had to stay off: with nothing of the
operator's in the set that could hold it, the operator was one detection away
from being blocked by their own Sentinel.

The wrappers made it worse from the other end. `scripts/deploy.ps1` matched the
captured SSH peer against `^\\d{1,3}(\\.\\d{1,3}){3}$`, called an IPv6 peer a
malformed capture, threw it away, and then warned that the allowlist might end
up empty. `scripts/deploy.sh` did not check at all and handed the address on to
be given a "/32".

Every test below names the state the operator would be left in if the behaviour
it pins were lost. Only documentation ranges appear here — 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32 — because this repository is
public.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[2]
COMMON_SH = REPO / "deploy" / "lib" / "common.sh"
INSTALL_SH = REPO / "deploy" / "install.sh"
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
DEPLOY_PS1 = REPO / "scripts" / "deploy.ps1"
TABLE_NFT = REPO / "deploy" / "nftables" / "sentinel-table.nft"
DEPLOY_PREFLIGHT = REPO / "deploy" / "preflight.sh"
SMOKE_TEST_SH = REPO / "scripts" / "smoke-test.sh"
COMMANDS_PY = REPO / "executor" / "commands.py"

BASH = shutil.which("bash")
PS = shutil.which("pwsh") or shutil.which("powershell.exe")

pytestmark = pytest.mark.skipif(BASH is None, reason="no bash on PATH")


def _env(**extra: str) -> dict[str, str]:
    """The caller's environment plus the overrides.

    Not a minimal env: on Windows, CreateProcess resolves the executable using
    the PATH it is handed, and a hand-built one finds WSL's bash instead of Git
    Bash — which fails with a Windows service error that looks nothing like a
    test failure.
    """
    return {**os.environ, "NO_COLOR": "1", **extra}


def run_bash(script: str, **env: str) -> subprocess.CompletedProcess:
    """Run a script by handing it to bash on STDIN, from the repository root.

    Never as `bash -c <script>`: on Windows that goes through the process
    command line, where quoting is rewritten in transit and a script this size
    arrives with an unterminated string. Never as a file path either — an
    absolute `C:/…` reaches MSYS bash as a relative path under a directory
    called `C:`. Stdin has neither problem, and cwd=REPO means every path inside
    the script can stay relative.
    """
    return subprocess.run(
        [BASH], input=script, cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=_env(**env),
    )


def run_powershell(script: str) -> subprocess.CompletedProcess:
    """Run a PowerShell script from a file.

    NOT `-Command -`: PowerShell reads stdin a line at a time and a multi-line
    `function … { … }` never gets defined, so every call returns nothing and a
    test asserting on the output goes green against an empty string. And not
    `-Command <script>` either, for the same argv-quoting reason as run_bash.
    The BOM is there because PowerShell 5.1 reads a BOM-less file as ANSI, which
    mangles the em-dashes in deploy.ps1's own comments.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.ps1"
        path.write_text(script, encoding="utf-8-sig")
        return subprocess.run(
            [PS, "-NoProfile", "-File", str(path)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )


def _install_function(name: str) -> str:
    """One function lifted verbatim out of the shipped deploy/install.sh.

    Cut from the file, never retyped. A test that carries its own copy of the
    logic passes while the code that ships is broken — this repository has
    shipped that mistake once already.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\(\) \{{.*?^\}}", text, re.S | re.M)
    assert match, f"{name}() not found in install.sh"
    return match.group(0)


# ---------------------------------------------------------------------------
# Harness for step_nftables
# ---------------------------------------------------------------------------
# There is no nft on this machine and there must not be one: what is under test
# is which SET each address is written to, and that is visible in the argv the
# step hands to nft. So nft is a shell function that records its argv, and
# public_ips / getent / install / chown / chmod are stubbed the same way. The
# step itself is the shipped one, extracted from install.sh at run time.
#
# Everything happens inside a directory bash makes for itself with mktemp, and
# the results come back on stdout in labelled sections. Nothing here builds a
# Windows path for bash to read: an absolute `C:/…` reaches MSYS bash as a
# relative path under a directory called `C:`, which is how a harness ends up
# testing an empty file.

HARNESS = r"""
set -euo pipefail
source deploy/lib/common.sh

work="$(mktemp -d)"
SCRIPT_DIR="deploy"
SENTINEL_PREFIX="${work}/opt"
SENTINEL_CONFIG_DIR="${work}/etc"
mkdir -p "$SENTINEL_CONFIG_DIR"
if [[ -n "${YAML:-}" ]]; then printf '%s\n' "$YAML" > "${SENTINEL_CONFIG_DIR}/sentinel.yaml"; fi

NFT_LOG="${work}/nft.log"
: > "$NFT_LOG"

# Records the whole argv, and answers `list set` so the read-back at the end of
# the step has something to print.
#
# Three knobs, because three different things the KERNEL can do have to be told
# apart in the step's output:
#
#   NFT_LIST_FAILS  the read-back fails, so an unreadable set is reported as
#                   unknown rather than as empty.
#   NFT_ADD_FAILS   space-separated elements this nft REFUSES. Without it every
#                   `add` returned 0, so nft_allowlist_add's whole refusal
#                   branch was exercised by nothing and could be replaced with
#                   "count every refusal as accepted" without a test noticing.
#   NFT_ADD_ERR     what it prints on stderr when it refuses. The default is the
#                   wording nft 1.0.9 produced on both production hosts for a v6
#                   element pushed at an ipv4_addr set — the exact failure this
#                   whole change exists to stop swallowing.
#   NFT_CHECK_FAILS `nft -c -f` refuses the persisted file.
#   NFT_CHECK_ERR   what it says while refusing. "File exists" is the answer the
#                   real kernel gives, because the elements were added a moment
#                   earlier; anything else is a broken file.
#
# `-c -f` also copies the file it was handed into the log, one `checked| ` line
# per line of the file. That is what makes the ORDER checkable: a check that ran
# before the file was written would show an empty or stale body, and asserting
# only that the command appeared would pass on exactly that.
nft() {
    printf '%s\n' "$*" >> "$NFT_LOG"
    case "${1:-}" in
        -c)
            if [[ "${2:-}" == "-f" && -f "${3:-}" ]]; then
                while IFS= read -r __l; do
                    printf 'checked| %s\n' "$__l" >> "$NFT_LOG"
                done < "$3"
            fi
            if [[ -n "${NFT_CHECK_FAILS:-}" ]]; then
                printf '%s\n' "${NFT_CHECK_ERR:-Error: syntax error, unexpected string}" >&2
                return 1
            fi
            ;;
        list)
            if [[ -n "${NFT_LIST_FAILS:-}" ]]; then
                printf 'Error: No such file or directory\n' >&2
                return 1
            fi
            if [[ "${2:-}" == "chain" ]]; then
                # step_nftables now reads each chain back after the load and
                # compares its rule count with the shipped file (six rules
                # per chain, see test_nftables_idempotent.py — including
                # forward's `daddr` rules, which a stub built only out of
                # `saddr` lines would not exercise). This file's tests are
                # not about that check, so the stub answers with a
                # correctly-sized, un-doubled chain shaped like the REAL
                # `nft list chain inet sentinel <input|forward>` output —
                # otherwise every test here would pick up a spurious
                # "rules are MISSING" or "may have doubled" warning that has
                # nothing to do with what it is testing.
                local __chain="${5:-?}" __i
                local -a __rules
                if [[ "$__chain" == "input" ]]; then
                    __rules=(
                        'ip saddr @allowlist_v4 accept'
                        'ip6 saddr @allowlist_v6 accept'
                        'ip saddr @watchlist_v4 counter packets 0 bytes 0'
                        'ip6 saddr @watchlist_v6 counter packets 0 bytes 0'
                        'ip saddr @blocklist_v4 counter packets 0 bytes 0 drop'
                        'ip6 saddr @blocklist_v6 counter packets 0 bytes 0 drop'
                    )
                else
                    __rules=(
                        'ip saddr @allowlist_v4 accept'
                        'ip6 saddr @allowlist_v6 accept'
                        'ip saddr @blocklist_v4 counter packets 0 bytes 0 drop'
                        'ip daddr @blocklist_v4 counter packets 0 bytes 0 drop'
                        'ip6 saddr @blocklist_v6 counter packets 0 bytes 0 drop'
                        'ip6 daddr @blocklist_v6 counter packets 0 bytes 0 drop'
                    )
                fi
                printf 'table inet sentinel {\n\tchain %s {\n' "$__chain"
                for ((__i = 0; __i < 6; __i++)); do
                    printf '\t\t%s\n' "${__rules[__i]}"
                done
                printf '\t}\n}\n'
                return 0
            fi
            printf 'table inet sentinel {\n    set %s {\n    }\n}\n' "${5:-?}"
            ;;
        add)
            # argv is: add element inet sentinel <set> "{ <element> }"
            local elem="${6:-}" pat
            elem="${elem#\{ }"; elem="${elem% \}}"
            for pat in ${NFT_ADD_FAILS:-}; do
                if [[ "$elem" == "$pat" ]]; then
                    printf '%s\n' "${NFT_ADD_ERR:-Error: Could not resolve hostname: Address family for hostname not supported}" >&2
                    return 1
                fi
            done
            ;;
    esac
    return 0
}

public_ips() { local a; for a in ${PUBLIC_IPS:-}; do printf '%s\n' "$a"; done; }

getent() {
    local a
    case "${1:-}" in
        ahostsv4) for a in ${GETENT_V4:-}; do printf '%s\n' "$a"; done ;;
        ahostsv6) for a in ${GETENT_V6:-}; do printf '%s\n' "$a"; done ;;
    esac
    return 0
}

# The real `install` would need root for -o/-g. Only the directory and the copy
# matter to this test.
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

# In a SUBSHELL, because the step can now `die`, and `die` calls `exit`. Run as
# a plain function that exit would end this script before a single section was
# printed, and every assertion below would fail on "the harness printed no NFT
# section" rather than on what the step did.
STEP_RC=0
( step_nftables ) > "${work}/step.out" || STEP_RC=$?

printf '===NFT===\n';       cat "$NFT_LOG"
printf '===PERSISTED===\n'; cat "${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft" 2>/dev/null || true
printf '===STDOUT===\n';    cat "${work}/step.out"
printf '===RC===\n%s\n' "$STEP_RC"
rm -rf "$work"
"""


class StepResult:
    def __init__(self, proc: subprocess.CompletedProcess) -> None:
        self.proc = proc
        self.stderr = proc.stderr
        body = proc.stdout
        self.nft = _section(body, "NFT")
        self.persisted = _section(body, "PERSISTED")
        self.stdout = _section(body, "STDOUT")
        self.rc = int(_section(body, "RC").strip())

    @property
    def added(self) -> list[str]:
        """The `add element` calls the step made, as `set element` pairs."""
        out = []
        for line in self.nft.splitlines():
            match = re.match(r"add element inet sentinel (\S+) \{ (\S+) \}$", line.strip())
            if match:
                out.append(f"{match.group(1)} {match.group(2)}")
        return out

    @property
    def persisted_pairs(self) -> list[str]:
        out = []
        for line in self.persisted.splitlines():
            match = re.match(r"add element inet sentinel (\S+) \{ (\S+) \}$", line.strip())
            if match:
                out.append(f"{match.group(1)} {match.group(2)}")
        return out

    @property
    def check_loaded(self) -> list[str]:
        """The lines `nft -c -f` was actually shown, in order.

        Not "was the command run": the point of the check is that it saw the
        FINISHED file, so what it read is the evidence, not that it was called.
        """
        return [l[len("checked| "):] for l in self.nft.splitlines()
                if l.startswith("checked| ")]


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


YAML_MIXED = """response:
  extra_allowlist:
    - "203.0.113.0/24"
    - "2001:db8:1::/48"
    - "198.51.100.7"
    - "garbage"
  auto_block: false
"""


# ---------------------------------------------------------------------------
# The address that could not be allowlisted
# ---------------------------------------------------------------------------
def test_an_ipv6_admin_address_lands_in_the_v6_set():
    """"operatorul a fost blocat de propriul Sentinel, fiindcă ajunge la server
    doar pe IPv6 și lista albă nu putea să-l conțină."

    The admin address is the one entry the allowlist exists for. Sent to
    allowlist_v4 with a "/32" on it, the kernel refuses it, `2>/dev/null` eats
    the refusal, and the operator is left outside a list that reports them
    inside it. Both the live element and the persisted line are checked: the
    persisted file is what comes back after a reboot, and an entry that exists
    only in the kernel is one the next reboot removes.
    """
    res = run_step(ADMIN_IP="2001:db8::1")
    assert "allowlist_v6 2001:db8::1/128" in res.added, res.nft
    assert "allowlist_v6 2001:db8::1/128" in res.persisted_pairs, res.persisted

    # And nowhere near the v4 set, in either form.
    v4_lines = [l for l in res.nft.splitlines() + res.persisted.splitlines()
                if "allowlist_v4" in l]
    assert not any("2001:db8" in l for l in v4_lines), v4_lines
    assert "2001:db8::1/32" not in res.nft + res.persisted


def test_an_ipv4_admin_address_still_gets_slash_32():
    """The repair must not move the v4 operator out of the set that holds them.

    Everything deployed so far reaches its host over IPv4 and is allowlisted by
    exactly this line. A family-routing change that sent it to allowlist_v6
    would lock out every existing installation on the next deploy.
    """
    res = run_step(ADMIN_IP="203.0.113.10")
    assert "allowlist_v4 203.0.113.10/32" in res.added, res.nft
    assert "allowlist_v4 203.0.113.10/32" in res.persisted_pairs, res.persisted
    assert not any("203.0.113.10" in l for l in res.nft.splitlines()
                   if "allowlist_v6" in l)


def test_extra_allowlist_is_routed_by_family_and_prefixes_survive():
    """extra_allowlist is where the operator puts the uptime monitor and the
    office range. A v6 range sent to allowlist_v4 is refused by the kernel, so
    the monitor keeps being blockable while the config says it is not — and a
    prefix that lost its length would allowlist one host out of a /48.
    """
    res = run_step(YAML=YAML_MIXED)
    for expected in ("allowlist_v4 203.0.113.0/24",
                     "allowlist_v6 2001:db8:1::/48",
                     "allowlist_v4 198.51.100.7/32"):
        assert expected in res.added, f"{expected} missing from {res.nft}"
        assert expected in res.persisted_pairs, f"{expected} missing from {res.persisted}"


def test_a_malformed_extra_allowlist_entry_is_named_and_written_nowhere():
    """A typo in extra_allowlist used to be appended with a "/32", refused by
    the kernel and swallowed. The operator read a success line and believed an
    address was protected that was not in either set.

    So: never written, and never silent — the refusal names the value, because
    an entry the operator cannot see was rejected is an entry they will not fix.
    """
    res = run_step(YAML=YAML_MIXED)
    assert "garbage" not in res.nft, res.nft
    assert "garbage" not in res.persisted, res.persisted
    assert "garbage" in res.stderr, res.stderr
    assert "extra_allowlist" in res.stderr, res.stderr


# ---------------------------------------------------------------------------
# The two YAML shapes this one key is actually written in
# ---------------------------------------------------------------------------
def _entries_run(yaml_text: str, preamble: str = "") -> subprocess.CompletedProcess:
    """The SHIPPED extra_allowlist_entries(), run over one config file.

    Cut out of install.sh, not retyped, and handed a file bash makes for itself
    — an absolute `C:/…` path would reach MSYS bash as a relative one. The
    process is returned whole because the EXIT STATUS is part of what this
    reader says: 3 means "the key is there and I could not read it", which the
    caller turns into a warning.
    """
    script = (
        preamble
        + _install_function("extra_allowlist_entries")
        + '\nf="$(mktemp)"\ncat > "$f" <<\'__YAML__\'\n'
        + yaml_text
        + '\n__YAML__\nextra_allowlist_entries "$f"\nrc=$?\nrm -f "$f"\nexit $rc\n'
    )
    return run_bash(script)


def _entries(yaml_text: str) -> list[str]:
    proc = _entries_run(yaml_text)
    assert proc.returncode == 0, f"rc={proc.returncode}: {proc.stderr}"
    return proc.stdout.splitlines()


def test_the_flow_form_the_installer_writes_is_read():
    """The production bug. `config/sentinel.yaml.tmpl` writes
    `extra_allowlist: [@@EXTRA_ALLOWLIST@@]` — the FLOW form — and the reader
    understood only the block form, so on every host this installer configured
    the operator's entries reached nftables not at all.

    Both production hosts carry `extra_allowlist: ["<addr>", "<addr>"]`, which
    means the addresses the operator hand-added on 6 September were never in the
    set, and step 29 printed a green count that had never counted them.
    """
    got = _entries(
        'response:\n'
        '  extra_allowlist: [ "203.0.113.0/24", \'2001:db8:1::/48\', 198.51.100.7 ]  # note\n'
        '  auto_block: false\n'
    )
    assert got == ["203.0.113.0/24", "2001:db8:1::/48", "198.51.100.7"], got


@pytest.mark.parametrize(
    "flow,expected",
    [("[]", []),                                  # what the template writes
     ("[ ]", []),                                 # the same, hand-spaced
     ('["203.0.113.0/24", ]', ["203.0.113.0/24"]),  # a trailing comma
     ],
)
def test_an_empty_slot_in_the_flow_form_is_not_an_entry(flow, expected):
    """`extra_allowlist: []` is what the template writes when no admin address
    was determined, and a trailing comma is what a hand edit leaves behind.

    An empty string handed on as an entry becomes `warn "…: '' is not an IP
    address"` on every single install — a warning about something the operator
    never wrote, printed every time, which is how they learn to skip the
    warnings and miss the one about their real typo.
    """
    got = _entries(f'response:\n  extra_allowlist: {flow}\n  auto_block: false\n')
    assert got == expected, got


def test_the_block_form_an_operator_types_by_hand_still_works():
    """The form the comment above the key in sentinel.yaml.tmpl invites, and the
    only one the old reader understood. Repairing the flow form by replacing the
    block form would move the outage rather than fix it: an operator who edited
    the file by hand would silently lose every entry they had added.
    """
    got = _entries('response:\n'
                   '  extra_allowlist:\n'
                   '    - "203.0.113.0/24"\n'
                   '    - 2001:db8:1::/48\n'
                   '\n'
                   "    - '198.51.100.7'\n"
                   '  auto_block: false\n')
    assert got == ["203.0.113.0/24", "2001:db8:1::/48", "198.51.100.7"], got


def test_a_commented_out_entry_is_not_ingested():
    """Commenting an entry out is how an operator parks one. If it came back
    anyway, an address they deliberately removed would keep being unblockable —
    and nothing on screen would say why.
    """
    got = _entries('response:\n'
                   '  extra_allowlist:\n'
                   '    - "203.0.113.0/24"\n'
                   '    #  - "198.51.100.99"\n'
                   '    - "2001:db8:1::/48"\n'
                   '  auto_block: false\n')
    assert got == ["203.0.113.0/24", "2001:db8:1::/48"], got


def test_the_block_form_stops_at_the_next_key():
    """A reader that ran past the end of the sequence would collect the values of
    whatever key came next. Those are not addresses, so the operator would get a
    warning per unrelated config line on every install.
    """
    got = _entries('response:\n'
                   '  extra_allowlist:\n'
                   '    - "203.0.113.0/24"\n'
                   '  auto_block: false\n'
                   '  never_block:\n'
                   '    - "198.51.100.99"\n')
    assert got == ["203.0.113.0/24"], got


def test_a_key_that_merely_ends_in_the_name_is_not_the_key():
    """`extra_allowlist:` is the key and `web_extra_allowlist:` is a different
    one. Read as the same key, addresses the operator scoped to something else
    would silently become firewall allowlist entries — the widest possible
    reading of a setting they wrote to be narrow.
    """
    got = _entries('response:\n'
                   '  web_extra_allowlist:\n'
                   '    - "198.51.100.99"\n'
                   '  extra_allowlist:\n'
                   '    - "203.0.113.0/24"\n')
    assert got == ["203.0.113.0/24"], got


def test_the_list_is_only_read_under_response():
    """Anchored under the top-level `response:` block, not merely at the start of
    a line.

    sentinel.yaml already carries an unrelated `ip_allowlist` under `web:`. The
    day `web:` is given an `extra_allowlist:` of its own — a list of addresses
    allowed to reach the dashboard — a reader anchored only at the start of the
    line would turn it into firewall policy without a word, and addresses scoped
    to one HTTP vhost would become unblockable everywhere.

    Both readers, because they run on the same file for the same purpose: the
    installer decides what goes into nftables, the executor decides what it
    refuses to block, and the two disagreeing is how an address is protected by
    one and dropped by the other.
    """
    yaml_text = ('web:\n'
                 '  extra_allowlist: ["198.51.100.99"]\n'
                 'response:\n'
                 '  extra_allowlist: ["203.0.113.5"]\n')
    assert _entries(yaml_text) == ["203.0.113.5"]
    assert _python_entries(yaml_text) == ["203.0.113.5"]

    # And a list at column 0, under nothing at all, is not this key either.
    assert _entries('extra_allowlist: ["198.51.100.99"]\n') == []
    assert _python_entries('extra_allowlist: ["198.51.100.99"]\n') == []


def test_a_hash_inside_a_quoted_block_entry_is_not_a_comment():
    """`- "203.0.113.5 # not a comment"` used to come out as `"203.0.113.5` —
    the comment was stripped before the quotes were, which left an unbalanced
    one glued to the address.

    What the operator saw was a warning naming a value they had not written,
    and no allowlist entry for the address they had. The flow form already got
    this right, so the two halves of the same reader disagreed.
    """
    got = _entries('response:\n'
                   '  extra_allowlist:\n'
                   '    - "203.0.113.5 # not a comment"\n'
                   '    - 198.51.100.7 # this one IS a comment\n')
    assert got == ["203.0.113.5 # not a comment", "198.51.100.7"], got


# --- the two readers of one key --------------------------------------------
#
# deploy/install.sh decides what goes into the nftables allowlist; the executor
# decides what it will refuse to block. Both read `response.extra_allowlist` out
# of the same file with their own hand-rolled reader, and when they disagree an
# address is protected by one and dropped by the other — with nothing on screen,
# because each of them is behaving correctly by its own lights.
READER_FIXTURES = [
    ("flow, as the template writes it",
     'response:\n  extra_allowlist: ["203.0.113.0/24", "2001:db8:1::/48"]\n',
     ["203.0.113.0/24", "2001:db8:1::/48"]),
    ("flow with a trailing comment",
     'response:\n  extra_allowlist: ["203.0.113.5"]  # nota\n',
     ["203.0.113.5"]),
    ("flow, empty",
     'response:\n  extra_allowlist: []\n', []),
    ("flow, single quotes",
     "response:\n  extra_allowlist: ['203.0.113.5', '2001:db8::1']\n",
     ["203.0.113.5", "2001:db8::1"]),
    ("flow, a # inside the quotes",
     'response:\n  extra_allowlist: ["203.0.113.5 # x"]\n',
     ["203.0.113.5 # x"]),
    # The bracket that closes the sequence is found by scanning past quotes, not
    # by `index(rest, "]")` or `endswith("]")`. Contrived-looking, but it is the
    # only input that separates a quote-aware scan from a naive one, and both
    # readers have to be scanning the same way or they part company on the next
    # shape somebody types.
    ("flow, a ] inside the quotes",
     'response:\n  extra_allowlist: ["203.0.113.5]", "198.51.100.7"]\n',
     ["203.0.113.5]", "198.51.100.7"]),
    ("flow, a trailing comma",
     'response:\n  extra_allowlist: ["203.0.113.5", ]\n', ["203.0.113.5"]),
    ("flow, wrapped onto a second line",
     'response:\n  extra_allowlist: ["203.0.113.5",\n    "198.51.100.7"]\n', []),
    ("block, as an operator types it",
     'response:\n  extra_allowlist:\n    - "203.0.113.0/24"\n    - 2001:db8:1::/48\n',
     ["203.0.113.0/24", "2001:db8:1::/48"]),
    ("block with a trailing comment",
     'response:\n  extra_allowlist:\n    - 203.0.113.5  # nota\n', ["203.0.113.5"]),
    ("block, a # inside the quotes",
     'response:\n  extra_allowlist:\n    - "203.0.113.5 # x"\n', ["203.0.113.5 # x"]),
    ("block, single quotes",
     "response:\n  extra_allowlist:\n    - '203.0.113.5'\n", ["203.0.113.5"]),
    ("block, a commented-out entry",
     'response:\n  extra_allowlist:\n    - "203.0.113.5"\n'
     '    #  - "198.51.100.99"\n    - "198.51.100.7"\n',
     ["203.0.113.5", "198.51.100.7"]),
    ("block, stopped by the next key",
     'response:\n  extra_allowlist:\n    - "203.0.113.5"\n'
     '  auto_block: false\n  never_block:\n    - "198.51.100.99"\n',
     ["203.0.113.5"]),
    ("a key that merely ends in the name",
     'response:\n  web_extra_allowlist:\n    - "198.51.100.99"\n'
     '  extra_allowlist:\n    - "203.0.113.5"\n',
     ["203.0.113.5"]),
    ("the same key under a different top-level block",
     'web:\n  extra_allowlist: ["198.51.100.99"]\n'
     'response:\n  extra_allowlist: ["203.0.113.5"]\n',
     ["203.0.113.5"]),
    ("an unterminated quote is handed on whole, not repaired",
     'response:\n  extra_allowlist:\n    - "203.0.113.5\n', ['"203.0.113.5']),
]


def _python_entries(yaml_text: str) -> list[str]:
    """The SHIPPED executor reader, over the same text."""
    from executor.sentinel_executor import _operator_allowlist

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sentinel.yaml"
        path.write_text(yaml_text, encoding="utf-8")
        return _operator_allowlist(str(path))


@pytest.mark.parametrize("label,yaml_text,expected",
                         READER_FIXTURES, ids=[f[0] for f in READER_FIXTURES])
def test_both_readers_of_the_allowlist_agree(label, yaml_text, expected):
    """The installer's awk and the executor's Python must answer identically.

    They did not. `extra_allowlist: ["203.0.113.5"]  # nota` — a flow list with
    a comment after it — made the executor return NOTHING, because it required
    the line to end in "]", while the installer returned the entry. So nftables
    allowlisted the address and the executor, which holds the never-block list,
    did not know about it: the address was one detection away from being blocked
    by a process that had been told it was safe, and the config said so in
    writing.

    The ENTRIES are compared here, not the exit status: the installer reader
    also signals "I could not read this" (status 3, checked in the test below),
    and the executor has no operator to tell. What both of them must agree on is
    which addresses come out.
    """
    proc = _entries_run(yaml_text)
    assert proc.stderr.strip() == "", proc.stderr
    assert proc.stdout.splitlines() == expected, "installer reader"
    assert _python_entries(yaml_text) == expected, "executor reader"


def test_a_wrapped_flow_list_is_reported_by_the_reader_not_guessed_at():
    """A flow list continued on a second line is a shape neither reader follows.

    Reading half of it would allowlist some entries and drop the rest without
    saying which, so nothing is taken from it — and the reader says so, with
    exit status 3, because "the list is empty" and "the list is there and I
    could not read it" are different facts and the operator can only act on the
    second if they are told it happened.
    """
    proc = _entries_run('response:\n'
                        '  extra_allowlist: ["203.0.113.5",\n'
                        '    "198.51.100.7"]\n')
    assert proc.returncode == 3, (proc.returncode, proc.stdout, proc.stderr)
    assert proc.stdout.strip() == "", proc.stdout

    # A list that IS on one line does not raise it.
    ok_proc = _entries_run('response:\n  extra_allowlist: ["203.0.113.5"]\n')
    assert ok_proc.returncode == 0, ok_proc.stderr


def test_a_reader_that_cannot_run_is_not_silent():
    """`awk … 2>/dev/null || true` was what hid the previous version of this
    reader: it matched nothing on every host for the life of the installer, and
    the step printed a green line about entries it had never seen.

    A broken awk program produces no output — which is exactly what an empty
    list produces. The only thing that tells them apart is the complaint and the
    exit status, and both of those were being thrown away.
    """
    # `awk` replaced by a shell function; bash resolves functions before PATH,
    # so the SHIPPED reader is the one being run, with a broken awk under it.
    proc = _entries_run(
        'response:\n  extra_allowlist: ["203.0.113.5"]\n',
        preamble='awk() { printf "awk: syntax error at source line 1\\n" >&2; return 2; }\n')
    assert proc.returncode != 0, "a failed reader reported success"
    assert "syntax error" in proc.stderr, proc.stderr


def test_the_flow_form_reaches_the_nftables_sets():
    """The end-to-end version of the production bug: not just that the reader
    parses the flow form, but that step 29 puts what it read into the two sets.
    A parser fixed in isolation and never wired in would leave the operator
    exactly where they were.
    """
    res = run_step(YAML='response:\n'
                        '  extra_allowlist: ["203.0.113.0/24", "2001:db8:1::/48"]\n'
                        '  auto_block: false\n')
    assert "allowlist_v4 203.0.113.0/24" in res.added, res.nft
    assert "allowlist_v6 2001:db8:1::/48" in res.added, res.nft
    assert "allowlist_v6 2001:db8:1::/48" in res.persisted_pairs, res.persisted


# ---------------------------------------------------------------------------
# The same address from several sources
# ---------------------------------------------------------------------------
def test_an_address_arriving_from_several_sources_is_added_once():
    """Step 26 seeds the admin address into `response.extra_allowlist`, so now
    that that list is read it arrives at step 29 twice — and a host that answers
    on an address it also lists there brings it a third time.

    Without de-duplication the second add comes back EEXIST, is counted as
    accepted, and the "N/M accepted" line stops describing the set underneath
    it. The persisted file grows a duplicate line per install, so the number the
    operator reads drifts further from the truth on every re-run.
    """
    res = run_step(
        ADMIN_IP="2001:db8::1",
        YAML='response:\n'
             '  extra_allowlist:\n'
             '    - "2001:db8::1"\n'
             '    - "203.0.113.10"\n'
             '  auto_block: false\n',
        PUBLIC_IPS="2001:db8::1 203.0.113.10",
    )
    for pair in ("allowlist_v6 2001:db8::1/128", "allowlist_v4 203.0.113.10/32"):
        assert res.added.count(pair) == 1, f"{pair} added {res.added.count(pair)}x:\n{res.nft}"
        assert res.persisted_pairs.count(pair) == 1, res.persisted
    # Four v4 defaults plus one, three v6 defaults plus one — the counts the
    # operator reads are the de-duplicated ones.
    assert re.search(r"5/5 IPv4 and 4/4 IPv6", res.stdout), res.stdout


def test_the_hosts_own_ipv6_addresses_are_no_longer_skipped():
    """`[[ "$ip" == *:* ]] || allow+=(…)` dropped every address of the host's
    own that had a colon in it.

    Sentinel blocking one of the host's own addresses black-holes traffic
    between the services on it — the dashboard, the aggregator, the executor
    socket's peer — and the operator sees a machine that has partly stopped
    talking to itself, with no block recorded against anything they recognise.
    """
    res = run_step(PUBLIC_IPS="192.0.2.5 2001:db8:abc::5")
    assert "allowlist_v4 192.0.2.5/32" in res.added, res.nft
    assert "allowlist_v6 2001:db8:abc::5/128" in res.added, res.nft
    assert "allowlist_v6 2001:db8:abc::5/128" in res.persisted_pairs, res.persisted


def test_both_api_hosts_are_resolved_on_both_families():
    """Blocking Telegram removes the only channel Sentinel can speak on, and
    blocking Anthropic removes its analysis — neither failure has a symptom
    other than silence. Only ahostsv4 was consulted, so the v6 addresses those
    names resolve to were never protected on a host that reaches them over IPv6.
    """
    res = run_step(GETENT_V4="192.0.2.20", GETENT_V6="2001:db8:f::20")
    assert "allowlist_v4 192.0.2.20/32" in res.added, res.nft
    assert "allowlist_v6 2001:db8:f::20/128" in res.added, res.nft


def test_a_v4_mapped_resolution_does_not_become_a_v6_element():
    """glibc's `getent ahostsv6` answers with ::ffff:a.b.c.d on a host with no
    IPv6. Written to allowlist_v6 that element can never match a packet — in an
    inet table an IPv4 packet is matched by `ip saddr` against the v4 set — so
    the set would fill up with entries that look right and accept nothing.
    """
    res = run_step(GETENT_V4="192.0.2.20", GETENT_V6="::ffff:192.0.2.20")
    assert not any("ffff" in pair for pair in res.added), res.nft
    assert not any("ffff" in pair for pair in res.persisted_pairs), res.persisted
    assert "allowlist_v4 192.0.2.20/32" in res.added
    # And exactly once: the mapped form folds onto the address already there.
    assert res.added.count("allowlist_v4 192.0.2.20/32") == 1, res.nft


# ---------------------------------------------------------------------------
# A host with no IPv6 at all must be quiet
# ---------------------------------------------------------------------------
def test_a_host_without_ipv6_gets_the_v6_defaults_and_says_nothing_about_it():
    """Most hosts have no IPv6. If the new path warned about that, every deploy
    would end with a warning nobody can act on — and a warning that fires on
    every run is a warning the operator stops reading, which is how the real one
    gets missed.
    """
    res = run_step(ADMIN_IP="203.0.113.10", PUBLIC_IPS="192.0.2.5",
                   GETENT_V4="192.0.2.20", GETENT_V6="")
    assert res.proc.returncode == 0
    assert res.stderr.strip() == "", res.stderr
    v6 = [p for p in res.added if p.startswith("allowlist_v6 ")]
    assert v6 == ["allowlist_v6 ::1/128",
                  "allowlist_v6 fc00::/7",
                  "allowlist_v6 fe80::/10"], v6


def test_the_static_v6_defaults_are_the_ones_that_were_decided_on():
    """Loopback, ULA and link-local, and no more.

    fe80::/10 is in on purpose: neighbour discovery and router advertisements
    live there, so a block landing on a fe80:: source does not drop one peer, it
    takes the host off IPv6 entirely. Adding a routable range here by accident
    would be the opposite mistake — an allowlist entry that makes real attackers
    unblockable.
    """
    body = _install_function("step_nftables")
    match = re.search(r"local -a ALLOW_V6=\((.*?)\)", body)
    assert match, "step_nftables no longer declares ALLOW_V6"
    assert match.group(1).split() == ['"::1/128"', '"fc00::/7"', '"fe80::/10"']

    match4 = re.search(r"local -a ALLOW_V4=\((.*?)\)", body)
    assert match4, "step_nftables no longer declares ALLOW_V4"
    assert match4.group(1).split() == ['"127.0.0.0/8"', '"10.0.0.0/8"',
                                       '"172.16.0.0/12"', '"192.168.0.0/16"']


# ---------------------------------------------------------------------------
# The report the operator reads
# ---------------------------------------------------------------------------
def test_both_sets_are_listed_and_counted_separately():
    """The step used to print `nft list set … allowlist_v4` and one total. On a
    host where every login is IPv6 the operator therefore read a list that could
    not contain their address, saw a plausible number, and concluded the
    allowlist was fine. Both sets are listed, and the counts are per family.
    """
    res = run_step(ADMIN_IP="2001:db8::1")
    assert "list set inet sentinel allowlist_v4" in res.nft, res.nft
    assert "list set inet sentinel allowlist_v6" in res.nft, res.nft
    assert re.search(r"\d+/\d+ IPv4 and \d+/\d+ IPv6", res.stdout), res.stdout


def test_a_set_that_cannot_be_read_back_is_unknown_not_empty():
    """"I could not read the set" and "the set is empty" are different facts.
    Reporting the first as the second is how a monitoring tool lies: the
    operator would be told their allowlist is in a state nobody actually
    observed.
    """
    res = run_step(ADMIN_IP="2001:db8::1", NFT_LIST_FAILS="1")
    assert "UNKNOWN" in res.stderr, res.stderr
    assert "allowlist_v6" in res.stderr, res.stderr


def test_a_kernel_refusal_is_named_and_not_counted_as_installed():
    """`2>/dev/null || true` is what hid this bug for the whole life of the
    installer: nft refused the element, the message went nowhere, and the count
    printed afterwards included it. The operator read "5 allowlist entries" and
    had four.

    So the refusal has to change what the operator SEES, in two ways at once: a
    named warning carrying nft's own words, and a total that is smaller than the
    number attempted. A count that still says 4/4 while a line above says an
    element was refused is the same lie with extra decoration.
    """
    res = run_step(ADMIN_IP="2001:db8::1", NFT_ADD_FAILS="2001:db8::1/128")

    # The element, the set, and what the kernel said — enough to act on without
    # re-running the installer to find out which entry it was.
    assert "2001:db8::1/128" in res.stderr, res.stderr
    assert "allowlist_v6" in res.stderr, res.stderr
    assert "Address family for hostname not supported" in res.stderr, res.stderr

    # Three of four v6 elements accepted; the v4 side untouched by any of it.
    assert re.search(r"4/4 IPv4 and 3/4 IPv6", res.stdout), res.stdout


def test_an_element_already_present_is_counted_and_not_warned_about():
    """A re-run, or `--force-step 29`, meets its own elements: `nft -f` adds to
    an existing table rather than replacing it, so every add comes back EEXIST.

    If that were reported as a refusal, the operator's second install would end
    in a screen of warnings about a correctly configured allowlist — and a
    warning that fires on every re-run is one they stop reading, which is how
    the real refusal gets missed.
    """
    already = ("127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 "
               "::1/128 fc00::/7 fe80::/10")
    res = run_step(NFT_ADD_FAILS=already,
                   NFT_ADD_ERR="Error: Could not process rule: File exists")
    assert re.search(r"4/4 IPv4 and 3/3 IPv6", res.stdout), res.stdout
    assert res.stderr.strip() == "", res.stderr


def test_a_refusal_does_not_stop_the_elements_after_it():
    """The step runs under `set -e`. If a refused element aborted it, one bad
    entry — a typo in extra_allowlist, an address a future kernel dislikes —
    would leave the allowlist half-filled AND skip everything after it: the
    persisted file, the read-back, and the rest of the install.

    The operator's own address is usually not first in the list.
    """
    res = run_step(NFT_ADD_FAILS="::1/128")

    v6 = [p for p in res.added if p.startswith("allowlist_v6 ")]
    assert v6 == ["allowlist_v6 ::1/128",
                  "allowlist_v6 fc00::/7",
                  "allowlist_v6 fe80::/10"], v6
    assert re.search(r"2/3 IPv6", res.stdout), res.stdout
    # And the step ran to its end: both sets were still read back.
    assert "list set inet sentinel allowlist_v4" in res.nft, res.nft
    assert "list set inet sentinel allowlist_v6" in res.nft, res.nft
    assert res.persisted_pairs, res.persisted


def test_the_report_says_auto_merge_can_shrink_the_listing():
    """Both sets carry `auto-merge`, so the kernel coalesces overlapping and
    adjacent elements — on production 17 persisted lines are 9 live elements.

    Unexplained, "I added 17 and the listing shows 9" reads exactly like the
    silent-refusal bug this step was rewritten for, and an operator who cannot
    tell the two apart has to treat every install as suspect.
    """
    res = run_step(ADMIN_IP="2001:db8::1")
    assert "auto-merge" in res.stdout, res.stdout
    assert "fewer" in res.stdout.lower(), res.stdout


# ---------------------------------------------------------------------------
# The persisted file is what the executor reloads
# ---------------------------------------------------------------------------
def test_the_persisted_v6_lines_are_in_the_syntax_the_executor_reloads():
    """After a reboot the table is gone and executor/commands.py recreates it by
    running `nft -f` over this file. A v6 line in a shape nft does not accept
    would take the WHOLE file down with it — table restored, allowlist not, and
    the next block placed against an unprotected admin address.
    """
    res = run_step(ADMIN_IP="2001:db8::1")
    v6_lines = [l.strip() for l in res.persisted.splitlines() if "allowlist_v6" in l]
    assert v6_lines, res.persisted
    for line in v6_lines:
        assert re.fullmatch(r"add element inet sentinel allowlist_v6 \{ \S+ \}", line), line

    # The same shape executor/commands.py appends when `/allow` adds an address,
    # so the two writers cannot drift into two syntaxes for one file.
    commands = COMMANDS_PY.read_text(encoding="utf-8")
    assert 'f"add element inet sentinel {set_name} {{ {element} }}"' in commands
    assert '"allowlist_v4" if network.version == 4 else "allowlist_v6"' in commands


def test_an_element_the_kernel_refused_is_not_persisted():
    """The reboot inversion.

    The step wrote every element it had COLLECTED into
    /opt/sentinel/libexec/sentinel-allowlist.nft, refusals included, and
    executor/commands.py reloads that file with one `nft -f` — one transaction.
    A single line the kernel refuses rolls the whole thing back, so a host with
    ONE bad entry in extra_allowlist came back from a reboot with the drop rules
    restored and the allowlist EMPTY: the operator's own address included.

    "Rebooting is always a way out of a self-inflicted block" is a guarantee the
    operator has been told to rely on, and that turned it into its opposite.
    """
    res = run_step(ADMIN_IP="2001:db8::1", NFT_ADD_FAILS="fc00::/7")

    assert "allowlist_v6 fc00::/7" in res.added, res.nft          # it was tried
    assert "allowlist_v6 fc00::/7" not in res.persisted_pairs, res.persisted
    # and everything the kernel DID take is there, in both families.
    for pair in ("allowlist_v6 ::1/128", "allowlist_v6 fe80::/10",
                 "allowlist_v6 2001:db8::1/128", "allowlist_v4 127.0.0.0/8"):
        assert pair in res.persisted_pairs, f"{pair} missing from:\n{res.persisted}"


def test_an_ipv4_element_the_kernel_refused_is_not_persisted():
    """The same reboot inversion, on the family every deployed host actually
    uses: the persisted file on both production hosts is IPv4 only, so a v4
    line the kernel refused is the one that would roll the whole allowlist
    back at the next reboot and leave the operator's address out of it.

    The v6 twin of this test could not see the v4 persist loop regress, and
    that loop is the one in use.
    """
    res = run_step(ADMIN_IP="203.0.113.7", NFT_ADD_FAILS="10.0.0.0/8")

    assert "allowlist_v4 10.0.0.0/8" in res.added, res.nft            # it was tried
    assert "allowlist_v4 10.0.0.0/8" not in res.persisted_pairs, res.persisted
    for pair in ("allowlist_v4 127.0.0.0/8", "allowlist_v4 203.0.113.7/32",
                 "allowlist_v6 ::1/128"):
        assert pair in res.persisted_pairs, f"{pair} missing from:\n{res.persisted}"


def test_an_element_the_kernel_already_had_is_persisted():
    """A re-run, or `--force-step 29`, meets its own elements and every add comes
    back EEXIST. Those elements ARE in the set, so they belong in the file that
    puts them back after a reboot.

    Dropping them would mean the second install of a host produced an
    allowlist file that restores nothing — the same lockout as a refusal, from
    the opposite direction.
    """
    res = run_step(ADMIN_IP="2001:db8::1",
                   NFT_ADD_FAILS="::1/128 127.0.0.0/8",
                   NFT_ADD_ERR="Error: Could not process rule: File exists")
    assert "allowlist_v6 ::1/128" in res.persisted_pairs, res.persisted
    assert "allowlist_v4 127.0.0.0/8" in res.persisted_pairs, res.persisted
    assert res.stderr.strip() == "", res.stderr


def test_the_persisted_file_is_check_loaded_after_it_has_been_written():
    """A file on disk is not proof that anything can load it.

    `nft -c -f` runs the same parse and the same evaluation the executor's
    `nft -f` will run at startup, and stops before the commit — so a file the
    executor could not load is found now, with an operator watching, instead of
    after a reboot with the allowlist gone.

    What is asserted is what the check SAW, not that the command was issued: a
    check run before the file was written would be issued exactly the same way
    and would prove nothing.
    """
    res = run_step(ADMIN_IP="2001:db8::1", PUBLIC_IPS="192.0.2.5")
    assert res.check_loaded, ("`nft -c -f` never read the persisted file:\n"
                              + res.nft)
    # It read the finished file: byte for byte what is on disk.
    assert res.check_loaded == res.persisted.splitlines(), (
        res.check_loaded, res.persisted)
    assert "add element inet sentinel allowlist_v6 { 2001:db8::1/128 }" in res.check_loaded


def test_the_kernel_saying_the_elements_are_already_there_is_not_a_failure():
    """`nft -c -f` on this file meets the elements that were added to the kernel
    a moment earlier, so the kernel answers "File exists".

    That answer is the PROOF wanted here — nft parses and evaluates the whole
    file before it talks to the kernel, so reaching EEXIST means every line
    parsed and every set name resolved. Treated as a failure it would abort every
    single install on a host where nft reports it.
    """
    res = run_step(ADMIN_IP="2001:db8::1", NFT_CHECK_FAILS="1",
                   NFT_CHECK_ERR="Error: Could not process rule: File exists")
    assert res.rc == 0
    assert re.search(r"allowlist persisted for restart", res.stdout), res.stdout
    assert "already present" in res.stdout, res.stdout


def test_a_persisted_file_the_check_rejects_stops_the_install():
    """If the file that comes back after a reboot does not load, the operator has
    a host whose allowlist silently disappears the next time it restarts.

    That is not something to warn about and carry on from, because the warning
    is read once and the reboot happens months later. The install stops, and
    stopping here is safe: the chains are `policy accept` and the blocklist sets
    are empty, so nothing is being dropped by anything.
    """
    res = run_step(_expect_rc=1, ADMIN_IP="2001:db8::1", NFT_CHECK_FAILS="1",
                   NFT_CHECK_ERR="Error: syntax error, unexpected junk")
    assert "sentinel-allowlist.nft" in res.stderr, res.stderr
    assert "syntax error, unexpected junk" in res.stderr, res.stderr
    assert "ONE transaction" in res.stderr, res.stderr


def test_the_step_says_how_many_entries_came_from_the_config():
    """The number the operator can act on directly: extra_allowlist is the list
    they edit. "0" next to a warning about a list that could not be read is a
    different problem from "3" of which one was refused, and without the count
    both look identical on screen.
    """
    res = run_step(YAML='response:\n'
                        '  extra_allowlist: ["203.0.113.0/24", "2001:db8:1::/48"]\n')
    assert "response.extra_allowlist supplied 2 entries" in res.stdout, res.stdout

    empty = run_step(YAML='response:\n  extra_allowlist: []\n')
    assert "response.extra_allowlist supplied 0 entries" in empty.stdout, empty.stdout


def test_a_flow_list_the_reader_could_not_follow_is_named_in_the_step():
    """An operator who wraps their list onto a second line — which is legal YAML
    — loses every entry in it. Silently, that reads as "extra_allowlist is
    empty", and they go on believing their office range is allowlisted.

    So the step names the situation and says what to do about it, and the count
    beside it says 0 rather than a number nobody produced.
    """
    res = run_step(YAML='response:\n'
                        '  extra_allowlist: ["203.0.113.5",\n'
                        '    "198.51.100.7"]\n')
    assert "flow list is not on one line" in res.stderr, res.stderr
    assert "extra_allowlist" in res.stderr, res.stderr
    assert "response.extra_allowlist supplied 0 entries" in res.stdout, res.stdout
    # And nothing from the half-read list reached the kernel.
    assert "203.0.113.5" not in res.nft, res.nft
    assert "198.51.100.7" not in res.nft, res.nft


def test_an_allowlist_entry_covering_the_whole_internet_is_named():
    """`0.0.0.0/0` or `::/0` in extra_allowlist is a legal element and it is
    honoured — an operator behind a filtering front end may mean it — but it
    means "never block anything on this family".

    Counted quietly among the others it reads like any other entry, and the
    operator is left with an auto-block that has been silently disabled for a
    whole address family while the report says the allowlist is fine.
    """
    res = run_step(YAML='response:\n'
                        '  extra_allowlist: ["0.0.0.0/0", "203.0.113.5"]\n')
    assert "ENTIRE internet" in res.stderr, res.stderr
    assert "0.0.0.0/0" in res.stderr, res.stderr
    # Honoured, not dropped: the behaviour is unchanged, only the silence is.
    assert "allowlist_v4 0.0.0.0/0" in res.added, res.nft
    # And an ordinary entry does not trip it.
    assert "203.0.113.5" not in res.stderr, res.stderr


def test_the_table_file_keeps_flags_interval_on_the_v6_set():
    """`flags interval` is what makes 2001:db8:1::/48 an element rather than an
    error. Without it every range in extra_allowlist is refused by the kernel
    and the operator's office network is blockable while the config says it is
    not.
    """
    text = TABLE_NFT.read_text(encoding="utf-8")
    match = re.search(r"set allowlist_v6 \{(.*?)\}", text, re.S)
    assert match, "allowlist_v6 is no longer declared in sentinel-table.nft"
    assert "type ipv6_addr" in match.group(1)
    assert "flags interval" in match.group(1), match.group(1)


def test_the_restored_allowlist_count_counts_entries_and_not_comments():
    """After a reboot the executor logs how many allowlist entries it put back,
    and that line is what an operator reads when they are wondering whether
    their own address came back.

    It counted every non-blank line, and the file this installer generates opens
    with five comment lines — so a host that restored three entries logged
    eight. A number that is always higher than the truth is worse than no number
    at all: it is the one an operator would use to decide the allowlist looked
    complete.
    """
    import commands as executor_commands

    with tempfile.TemporaryDirectory() as tmp:
        allow = Path(tmp) / "sentinel-allowlist.nft"
        allow.write_text(
            "# Generated by install.sh. Loaded by the executor when the table\n"
            "# is missing at startup. Blocks are deliberately NOT persisted.\n"
            "# Only elements the kernel accepted are listed: the executor loads\n"
            "# this file as ONE transaction, so one refused line would restore\n"
            "# nothing at all.\n"
            "add element inet sentinel allowlist_v4 { 127.0.0.0/8 }\n"
            "add element inet sentinel allowlist_v6 { ::1/128 }\n"
            "add element inet sentinel allowlist_v6 { 2001:db8::1/128 }\n",
            encoding="utf-8")
        table = Path(tmp) / "sentinel-table.nft"
        table.write_text("table inet sentinel {\n}\n", encoding="utf-8")

        calls: list[list[str]] = []

        def fake_run(argv, timeout=None):
            calls.append(list(argv))
            # "the table is missing" for the probe, success for every load.
            if argv[1:3] == ["list", "table"]:
                return {"exit_code": 1, "stdout": "", "stderr": "No such file"}
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        with mock.patch.object(executor_commands, "_run", fake_run), \
                mock.patch.object(executor_commands, "NFT_TABLE_FILE", str(table)), \
                mock.patch.object(executor_commands, "NFT_ALLOWLIST_FILE", str(allow)), \
                mock.patch.object(executor_commands, "log", lambda *a, **k: None):
            result = executor_commands.ensure_table()

    assert result["created"] is True, result
    assert result["allowlist_entries"] == 3, result
    # And it did reload the file rather than reporting a count of something it
    # never loaded.
    assert any(argv[1:] == ["-f", str(allow)] for argv in calls), calls


def test_the_ordering_comment_says_what_is_actually_true():
    """The comment claimed the allowlist was populated before the chains
    existed. It is not: one `nft -f` loads sets and chains together. A safety
    note that describes a mechanism the code does not have is worse than none —
    the next person preserves the wrong property.
    """
    body = _install_function("step_nftables")
    assert "ONE transaction" in body or "one transaction" in body, body
    assert "policy accept" in body
    assert "empty" in body
    assert "BEFORE the chain containing the drop rules exists" not in body

    table = TABLE_NFT.read_text(encoding="utf-8")
    assert "Populated by install.sh BEFORE the chains below exist" not in table


# ---------------------------------------------------------------------------
# The classifier itself
# ---------------------------------------------------------------------------
CLASSIFIER_CASES = [
    ("192.0.2.1", "v4"),
    ("203.0.113.0/24", "v4"),
    ("198.51.100.7/32", "v4"),
    ("2001:db8::1", "v6"),
    ("2001:db8:1::/48", "v6"),
    ("::1", "v6"),
    ("fe80::1", "v6"),
    ("fc00::/7", "v6"),
    ("::ffff:198.51.100.7", "v4"),
    ("1:2:3:4:5:6:7:8", "v6"),
    ("2001:0db8::1", "v6"),
    # The IPv4-compatible form: a dotted quad is only an address when it ENDS
    # the string. bash accepted "192.0.2.1::" as IPv6 while .NET refused it, and
    # two wrappers that disagree about what an address is are how the operator
    # is sent to fix an argument that worked.
    ("::192.0.2.1", "v6"),
    ("192.0.2.1::", "invalid"),
    ("", "invalid"),
    ("garbage", "invalid"),
    ("192.0.2", "invalid"),
    ("192.0.2.1.1", "invalid"),
    ("256.0.2.1", "invalid"),
    ("010.0.2.1", "invalid"),
    ("192.0.2.1/33", "invalid"),
    ("192.0.2.1/024", "invalid"),
    ("2001:db8::1/129", "invalid"),
    ("fe80::1%eth0", "invalid"),
    ("2001:db8::1::2", "invalid"),
    ("1:2:3:4:5:6:7:8:9", "invalid"),
    ("192.0.2.1//24", "invalid"),
]


# --- one case per guard, named after the guard -----------------------------
#
# CLASSIFIER_CASES above is a list of SHAPES an operator might type. This table
# is a different thing and is kept separate on purpose: it is written FROM the
# code, walking every `return 1` and every comparison in _ip_octet_ok,
# _ip_is_v4, _ip6_group_ok, _ip6_count, _ip_is_v6 and allowlist_element, and
# giving each one an input that lands on the wrong side of THAT test — plus, for
# the numeric ones, an input on the right side of it, one step away.
#
# The reason it exists: two rounds of review found guards that no test could
# distinguish. `nh + nt <= 7` could be relaxed to `<= 8` and `>= 96` to `>= 0`
# with the whole suite staying green, so `1:2:3:4:5:6:7:8::` — which nft and
# .NET both refuse — would have been called an address and handed to the kernel,
# and `::ffff:192.0.2.1/95` would have produced the element `192.0.2.1/-1`. A
# guard with no test is a guard the next edit deletes.
#
# The third column names the guard, so the mapping is visible without reading
# the shell. If a guard is ever removed, the case naming it should go with it.
GUARD_CASES = [
    # _ip_octet_ok: ^[0123456789]{1,3}$
    ("1234.0.2.1", "invalid", "_ip_octet_ok: ^[0123456789]{1,3}$ (four digits)"),
    ("a.0.2.1", "invalid", "_ip_octet_ok: ^[0123456789]{1,3}$ (not a digit)"),
    ("192.0.2.1\nfoo", "invalid",
     "_ip_octet_ok: ^...$ anchors at end of STRING, so a second line cannot ride along"),
    ("192.0.2.1 ", "invalid",
     "_ip_octet_ok: ^[0123456789]{1,3}$ — (( 10#$o )) alone would read "
     '"1 " as 1 and pass it on with the space still attached'),
    ("255.255.255.255", "v4", "_ip_octet_ok: ^[0123456789]{1,3}$ / <= 255, right side"),
    # _ip_octet_ok: the leading-zero refusal, and its "0" exemption
    ("010.0.2.1", "invalid", "_ip_octet_ok: leading zero is octal to some readers"),
    ("0.0.0.0", "v4", '_ip_octet_ok: the "$o" != "0" exemption in the leading-zero test'),
    # _ip_octet_ok: (( 10#$o <= 255 ))
    ("256.0.2.1", "invalid", "_ip_octet_ok: (( 10#$o <= 255 ))"),
    # _ip_is_v4: ^([^.]+)\.([^.]+)\.([^.]+)\.([^.]+)$
    ("192.0.2", "invalid", "_ip_is_v4: four fields, not three"),
    ("192.0.2.1.1", "invalid", "_ip_is_v4: four fields, not five"),
    ("192.0.2.1.", "invalid",
     "_ip_is_v4: [^.]+ rejects the empty field a trailing dot leaves"),
    ("192..2.1", "invalid", "_ip_is_v4: [^.]+ rejects an empty middle field"),
    ("192.0.2.1", "v4",
     "_ip_is_v4: the four groups are copied out of BASH_REMATCH before "
     "_ip_octet_ok replaces it"),
    # _ip6_group_ok: ^[0123456789abcdefABCDEF]{1,4}$
    ("::gggg", "invalid", "_ip6_group_ok: not a hex digit"),
    ("12345::1", "invalid", "_ip6_group_ok: five hex digits"),
    (":::", "invalid", "_ip6_group_ok: an empty group is not a group"),
    ("ffff::1", "v6", "_ip6_group_ok: four hex digits, right side"),
    ("FFFF::1", "v6", "_ip6_group_ok: the class carries A-F as well as a-f"),
    # _ip6_count: the empty fragment counts zero
    ("::", "v6", "_ip6_count: an empty side is zero groups, not an error"),
    ("garbage", "invalid", "_ip_is_v6: not an address at all"),
    # A colon at an end, or a second "::", leaves an EMPTY group, and an empty
    # group is what refuses all of these. The three `case`/`if` guards in
    # _ip_is_v6 that also refuse them are marked in the source as redundant —
    # see the falsification note there.
    (":1:2:3:4:5:6:7:8", "invalid", "_ip6_group_ok: an empty group is not a group"),
    ("1:2:3:4:5:6:7:8:", "invalid", "_ip6_group_ok: an empty group is not a group"),
    ("1::2:", "invalid", "_ip6_group_ok: an empty group is not a group"),
    (":1::2", "invalid", "_ip6_group_ok: an empty group is not a group"),
    # _ip_is_v6: the embedded dotted quad, restricted to the two nft accepts
    ("::192.0.2.1", "v6", "_ip_is_v6: dotted-quad lead == :: (right side)"),
    ("::ffff:198.51.100.7", "v4", "_ip_is_v6: dotted-quad lead == ::ffff: (right side)"),
    ("1:2:3:4:5:6:192.0.2.1", "invalid",
     "_ip_is_v6: dotted-quad lead — RFC 4291 allows it, nft 1.0.9 refuses it"),
    ("::1:2:3:192.0.2.1", "invalid", "_ip_is_v6: dotted-quad lead is not :: here"),
    ("::ffff:0:1.2.3.4", "invalid", "_ip_is_v6: dotted-quad lead is not ::ffff: here"),
    ("192.0.2.1::", "invalid", "_ip_is_v6: a quad that does not end the address"),
    ("::192.0.2.1:0", "invalid", "_ip_is_v6: a quad that does not end the address"),
    # _ip_is_v6: the quad itself is checked
    ("::192.0.2.256", "invalid", "_ip_is_v6: _ip_is_v4 on the embedded quad"),
    ("::1.2.3", "invalid", "_ip_is_v6: _ip_is_v4 on the embedded quad"),
    # _ip_is_v6: two "::"
    ("2001:db8::1::2", "invalid", "_ip6_group_ok: an empty group is not a group"),
    # _ip_is_v6: (( nh + nt <= 7 ))
    ("1:2:3:4:5:6:7::", "v6", "_ip_is_v6: nh + nt <= 7, right side (7 written)"),
    ("::1:2:3:4:5:6:7", "v6", "_ip_is_v6: nh + nt <= 7, right side (7 in the tail)"),
    ("1:2:3:4:5:6:7:8::", "invalid", "_ip_is_v6: nh + nt <= 7 (8 in the head)"),
    ("::1:2:3:4:5:6:7:8", "invalid", "_ip_is_v6: nh + nt <= 7 (8 in the tail)"),
    ("1:2:3:4::5:6:7:8", "invalid", "_ip_is_v6: nh + nt <= 7 (4 + 4)"),
    # _ip_is_v6: (( nh == 8 )) with no "::"
    ("1:2:3:4:5:6:7:8", "v6", "_ip_is_v6: nh == 8, right side"),
    ("1:2:3:4:5:6:7", "invalid", "_ip_is_v6: nh == 8 (seven groups)"),
    ("1:2:3:4:5:6:7:8:9", "invalid", "_ip_is_v6: nh == 8 (nine groups)"),
    # allowlist_element: the empty entry
    ("", "invalid", "allowlist_element: -z $entry"),
    # allowlist_element: a zone id
    ("fe80::1%eth0", "invalid", "allowlist_element: case $entry in *%*"),
    # allowlist_element: a second slash
    ("192.0.2.1//24", "invalid", "allowlist_element: case $rest in */*"),
    ("192.0.2.1/24/24", "invalid", "allowlist_element: case $rest in */*"),
    # allowlist_element: the prefix is 1..3 digits
    ("192.0.2.1/", "invalid", "allowlist_element: prefix ^[0123456789]{1,3}$ (empty)"),
    ("192.0.2.1/1234", "invalid", "allowlist_element: prefix ^[0123456789]{1,3}$ (four digits)"),
    ("192.0.2.1/2a", "invalid", "allowlist_element: prefix ^[0123456789]{1,3}$ (not a digit)"),
    # allowlist_element: the prefix leading-zero refusal and its "0" exemption
    ("192.0.2.1/024", "invalid", "allowlist_element: prefix leading zero"),
    ("203.0.113.0/0", "v4", 'allowlist_element: the "0" exemption in the prefix test'),
    # allowlist_element: (( 10#$prefix <= 32 ))
    ("192.0.2.1/32", "v4", "allowlist_element: prefix <= 32, right side"),
    ("192.0.2.1/33", "invalid", "allowlist_element: prefix <= 32"),
    # allowlist_element: (( 10#$prefix <= 128 ))
    ("2001:db8::1/128", "v6", "allowlist_element: prefix <= 128, right side"),
    ("2001:db8::1/129", "invalid", "allowlist_element: prefix <= 128"),
    # allowlist_element: the ::ffff: fold, and the /96 floor under it
    ("::198.51.100.7", "v6", "allowlist_element: the fold glob is ::ffff:, not :: "),
    ("::ffff:192.0.2.0/96", "v4", "allowlist_element: (( prefix >= 96 )), right side"),
    ("::ffff:192.0.2.0/95", "v6", "allowlist_element: (( prefix >= 96 ))"),
]


def _bash_families(values: list[str]) -> list[str]:
    args = " ".join(f'"{v}"' for v in values)
    proc = run_bash(
        f'source deploy/lib/common.sh\nfor v in {args}; do ip_family "$v" || true; done\n')
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.split()


def test_the_classifier_answers_each_form_correctly():
    """Everything this function calls an address is handed straight to
    `nft add element`. Too loose and garbage reaches the kernel under a "/32";
    too strict and a legitimate address of the operator's is refused, which is
    the lockout the allowlist exists to prevent.
    """
    got = _bash_families([v for v, _ in CLASSIFIER_CASES])
    assert got == [want for _, want in CLASSIFIER_CASES], list(
        zip([v for v, _ in CLASSIFIER_CASES], got))


def test_every_guard_in_the_classifier_has_an_input_that_needs_it():
    """Each `return 1` in the classifier, exercised by a value on the wrong side
    of exactly that test — and, where the test is a number, by one on the right
    side of it too.

    Two guards had reached production review with nothing able to tell them
    apart from their own absence. `nh + nt <= 7` widened to `<= 8` makes
    `1:2:3:4:5:6:7:8::` an address here, and nft refuses it: the operator would
    read that their address went into allowlist_v6 and it would not be there,
    which is the lockout this whole file is about. `>= 96` widened to `>= 0`
    turns `::ffff:192.0.2.1/95` into the element `192.0.2.1/-1`, which the
    kernel refuses in the same silence.

    Run as ONE bash invocation rather than parametrised: the classifier is
    sourced once for fifty-odd values, which is the difference between half a
    second and half a minute on a table this size.
    """
    values = [value for value, _, _ in GUARD_CASES]
    got = _bash_families(values)
    assert len(got) == len(GUARD_CASES), (
        f"bash answered {len(got)} times for {len(GUARD_CASES)} values — "
        f"the table was not fully run:\n{got}")
    wrong = [(value, guard, answer, want)
             for (value, want, guard), answer in zip(GUARD_CASES, got)
             if answer != want]
    assert not wrong, "\n".join(
        f"{value!r}: got {answer}, want {want}   [{guard}]"
        for value, guard, answer, want in wrong)


def test_the_guard_table_is_not_silently_empty():
    """A parametrised list that came out empty has already been shipped in this
    repository and skipped in silence for months. GUARD_CASES is a plain list,
    so it cannot be skipped — but it can be emptied by an edit, and then the
    test above would pass while checking nothing at all.
    """
    assert len(GUARD_CASES) >= 50, len(GUARD_CASES)
    assert all(guard.strip() for _, _, guard in GUARD_CASES), GUARD_CASES
    # Every function whose guards this table is written from is named by at
    # least one case. A whole function dropped out of the table is the shape
    # this check is for.
    named = " ".join(guard for _, _, guard in GUARD_CASES)
    for function in ("_ip_octet_ok", "_ip_is_v4", "_ip6_group_ok",
                     "_ip6_count", "_ip_is_v6", "allowlist_element"):
        assert function in named, f"no guard case names {function}"


def test_an_embedded_dotted_quad_is_only_the_two_shapes_nft_accepts():
    """nft 1.0.9 on production refuses
    `add element inet sentinel allowlist_v6 { 1:2:3:4:5:6:192.0.2.1/128 }`
    with "netlink: Error: set is not a map", while it accepts `::192.0.2.1/128`.

    RFC 4291 allows the first. nft is the layer that decides, so the classifier
    is narrowed to what nft takes: an address this code approves and the kernel
    refuses is the operator reading that they are allowlisted when they are not.
    Refused BY NAME here, which they can act on, instead of dropped by the
    kernel where nobody sees it.
    """
    assert _bash_families(["::192.0.2.1", "::ffff:198.51.100.7",
                           "1:2:3:4:5:6:192.0.2.1", "::1:2:3:192.0.2.1",
                           "::ffff:0:1.2.3.4"]) == \
        ["v6", "v4", "invalid", "invalid", "invalid"]

    # And the decision is written down where the next person meets the code.
    common = COMMON_SH.read_text(encoding="utf-8")
    body = common.split("_ip_is_v6() {", 1)[1].split("\nip_family()", 1)[0]
    assert "nft" in body and "RFC 4291" in body, body


@pytest.mark.parametrize(
    "entry,expected",
    [("198.51.100.7", "v4 198.51.100.7/32"),
     ("2001:db8::1", "v6 2001:db8::1/128"),
     ("203.0.113.0/24", "v4 203.0.113.0/24"),
     ("2001:db8:1::/48", "v6 2001:db8:1::/48"),
     ("::ffff:198.51.100.7", "v4 198.51.100.7/32"),
     ("::ffff:198.51.100.0/120", "v4 198.51.100.0/24"),
     # The /96 floor, from both sides. Below it the fold would subtract its way
     # to a negative prefix — `v4 192.0.2.0/-1` — which nft refuses, silently,
     # which is where this whole file started.
     ("::ffff:192.0.2.0/96", "v4 192.0.2.0/0"),
     ("::ffff:192.0.2.0/95", "v6 ::ffff:192.0.2.0/95")],
)
def test_the_element_gets_the_prefix_the_set_needs(entry, expected):
    """A bare address with no prefix is not an element of an interval set. If
    the "/32" and "/128" stopped being added the kernel would refuse every
    single-address entry, starting with the operator's own.
    """
    proc = run_bash(f'source deploy/lib/common.sh\nallowlist_element "{entry}"\n')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == expected


def test_a_non_ascii_digit_is_not_an_address():
    """Inside [[ =~ ]] a bracket RANGE is a collation range, so on glibc under a
    UTF-8 locale [0-9] also matches fullwidth and Arabic-Indic digits. An "address"
    built from those would be approved here and refused by nft — silently, which
    is the whole shape of the bug this file is about.

    Two assertions, and they are not of equal strength. The first is behaviour
    and holds anywhere. The second is TEXT, and it is here because the first
    cannot be falsified on this machine: MSYS bash does not widen [0-9] under
    any locale it has, so putting a range back leaves the behavioural check
    green here and breaks the installer on the glibc host it ships to. Saying
    that out loud beats a check that looks behavioural and is not.
    """
    exotic = "\uff11.\uff12.\uff13.\uff14"  # fullwidth 1.2.3.4
    proc = run_bash(f'source deploy/lib/common.sh\nip_family "{exotic}" || true\n',
                    LC_ALL="en_US.UTF-8", LANG="en_US.UTF-8")
    assert proc.stdout.strip() == "invalid", proc.stdout

    common = COMMON_SH.read_text(encoding="utf-8")
    classifier = common.split("_ip_octet_ok()", 1)[1].split("ip_family() {", 1)[0]
    assert "0123456789" in classifier, "the digit class went back to a range"
    assert not re.search(r"\[0-9", classifier),         "a [0-9] range is back in the classifier; on glibc it matches non-ASCII digits"
    assert not re.search(r"\[0-9a-f", classifier, re.I),         "a hex range is back in the classifier"


# ---------------------------------------------------------------------------
# The wrappers
# ---------------------------------------------------------------------------
def _ps1_code_only(text: str) -> str:
    """deploy.ps1 with its comments removed.

    The `<# … #>` block on Get-IpFamily quotes the regex it replaced, on
    purpose — that is what the comment is for. Searching the raw file would
    therefore find the old check forever and the test would be reporting on its
    own documentation.
    """
    without_blocks = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(l for l in without_blocks.splitlines()
                     if not l.lstrip().startswith("#"))


def test_deploy_ps1_no_longer_discards_ipv6_by_regex():
    """The exact line that threw the operator's address away.

    `-notmatch '^\\d{1,3}(\\.\\d{1,3}){3}$'` on the captured SSH peer, followed
    by "is not an IPv4 address; ignoring it" and then a warning that the
    allowlist may end up empty. On an IPv6-only path both were true and the
    second was caused by the first.
    """
    text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    code = _ps1_code_only(text)
    # The stripper has to have found the comment it is there to strip, or the
    # three assertions below are searching an unfiltered file and prove nothing.
    assert "Get-IpFamily" in code and len(code) < len(text)
    assert r"^\d{1,3}(\.\d{1,3}){3}$" not in code, "the IPv4-only regex is back"
    assert "is not an IPv4 address" not in code, "the message that discarded IPv6 is back"
    assert "function Get-IpFamily" in text
    assert "allowlist_v6" in code, "the operator is not told which set it goes into"


def test_deploy_sh_validates_the_captured_address():
    """deploy.sh captured `$SSH_CONNECTION` and passed the first field on with no
    check at all, so a failed capture — an empty or truncated value — travelled
    to the server and became an allowlist element. Both wrappers ship; both have
    to check.
    """
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert "ip_family_of" in text
    assert re.search(r"ip_family_of\s+\"\$ADMIN_IP\"", text), text[:0]


@pytest.mark.parametrize(
    "value,expected",
    [("2001:db8::1", "v6"), ("203.0.113.10", "v4"), ("garbage", "invalid")],
)
def test_deploy_sh_reuses_the_shipped_classifier(value, expected):
    """The wrapper and the installer have to agree about what an address is. If
    the wrapper called an IPv6 peer invalid and dropped it, the installer would
    never see the one address the operator can be reached at.
    """
    text = DEPLOY_SH.read_text(encoding="utf-8")
    match = re.search(r"^ip_family_of\(\) \{.*?^\}", text, re.S | re.M)
    assert match, "ip_family_of() not found in deploy.sh"
    proc = run_bash('REPO_ROOT="."\n' + match.group(0) + f'\nip_family_of "{value}"\n')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == expected, proc.stdout


def test_deploy_sh_says_it_could_not_check_rather_than_calling_it_fine():
    """If deploy/lib/common.sh cannot be read the address has not been judged.
    Reporting that as "valid" or as "invalid" both invent a fact; the wrapper
    says it did not check and lets the installer, which can, be the authority.
    """
    text = DEPLOY_SH.read_text(encoding="utf-8")
    match = re.search(r"^ip_family_of\(\) \{.*?^\}", text, re.S | re.M)
    proc = run_bash('REPO_ROOT="/nonexistent"\n' + match.group(0)
                    + '\nip_family_of "2001:db8::1"\n')
    assert proc.stdout.strip() == "unknown", proc.stdout
    assert "could not validate" in text


# --- PowerShell ------------------------------------------------------------
def _powershell_function(text: str, name: str) -> str:
    """(body) of `function X { … }`, by brace depth. Crude, but it only has to
    handle the one script and pytest has no PowerShell parser."""
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


def _ps_literal(value: str) -> str:
    """A value as a PowerShell expression, built from character codes.

    Not `'<value>'`. A guard case may be the empty string, or carry a newline —
    $'192.0.2.1\\ngarbage' is the input that shows _ip_octet_ok anchoring at the
    end of the STRING — and both of those end a single-quoted PowerShell literal
    in the wrong place. Quoting them by hand is how the parity table quietly
    stops containing the cases that matter.
    """
    if not value:
        return "''"
    return "(-join [char[]]@(" + ",".join(str(ord(c)) for c in value) + "))"


def _ps_families(values: list[str]) -> list[str]:
    body = _powershell_function(DEPLOY_PS1.read_text(encoding="utf-8-sig"), "Get-IpFamily")
    lines = ["function Get-IpFamily {" + body + "}"]
    for value in values:
        lines.append("Write-Output (Get-IpFamily " + _ps_literal(value) + ")")
    proc = run_powershell("\n".join(lines) + "\n")
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.split()


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_powershell_and_bash_classify_every_form_the_same_way():
    """deploy.sh and deploy.ps1 are both shipped. An operator working from
    PowerShell must get the same deployment as one working from bash: a wrapper
    that refuses an address the server would have accepted sends them off to fix
    a working argument, and one that accepts more fails halfway through a run,
    after the tarball has gone over.

    GUARD_CASES is in the input as well as CLASSIFIER_CASES, because the guards
    are exactly where two implementations drift apart. The live example is the
    embedded dotted quad: .NET's TryParse follows RFC 4291 and takes
    `1:2:3:4:5:6:192.0.2.1`, nft refuses it, and the PowerShell side therefore
    has to draw the same line by hand — or an operator deploying from Windows
    gets a different answer about their own address than one deploying from
    bash, and only one of them matches the server.
    """
    values = [v for v, _ in CLASSIFIER_CASES] + [v for v, _, _ in GUARD_CASES]
    expected = [w for _, w in CLASSIFIER_CASES] + [w for _, w, _ in GUARD_CASES]
    ps = _ps_families(values)
    assert len(ps) == len(values), (
        f"PowerShell answered {len(ps)} times for {len(values)} values; the "
        f"parity table was not fully run")
    assert ps == expected, [(v, g, w) for v, g, w in zip(values, ps, expected) if g != w]
    bash = _bash_families(values)
    assert ps == bash, [(v, p, b) for v, p, b in zip(values, ps, bash) if p != b]


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
def test_powershell_accepts_an_ipv6_ssh_peer():
    """The one case that broke a production host: the SSH peer arrives as an
    IPv6 literal and the wrapper has to keep it."""
    assert _ps_families(["2001:db8::1"]) == ["v6"]


# ---------------------------------------------------------------------------
# preflight: the operator has to be told which set, before anything is loaded
# ---------------------------------------------------------------------------
def _preflight_peer_block() -> str:
    """The admin-address report, cut out of the shipped preflight.sh.

    Top-level code, not a function, so it is bounded by its first and last
    lines rather than by braces. Both anchors are asserted: a cut that silently
    came back empty would make every assertion below pass against nothing.
    """
    text = DEPLOY_PREFLIGHT.read_text(encoding="utf-8")
    start = 'PEER="${ADMIN_IP:-$(ssh_peer_ip)}"'
    assert start in text, "preflight.sh no longer resolves PEER the way this test cuts"
    block = text.split(start, 1)[1]
    end = block.index("\nfor ip in $(public_ips); do")
    assert end > 0
    return start + block[:end]


@pytest.mark.parametrize(
    "peer,expect_family,expect_set",
    [("203.0.113.10", "IPv4", "allowlist_v4"),
     ("2001:db8::1", "IPv6", "allowlist_v6")],
)
def test_preflight_names_the_set_the_admin_address_goes_into(peer, expect_family, expect_set):
    """Preflight is the last thing the operator reads before the drop rules
    exist. "it goes in before any drop rule" was true of a v4 address and a
    comfortable lie for a v6 one, which went into a set nothing ever filled.
    Naming the set makes the claim checkable with one `nft list set`.
    """
    proc = run_bash("source deploy/lib/common.sh\n"
                    f'ADMIN_IP="{peer}"\n' + _preflight_peer_block() + "\n")
    assert proc.returncode == 0, proc.stderr
    assert peer in proc.stdout, proc.stdout
    assert expect_family in proc.stdout, proc.stdout
    assert expect_set in proc.stdout, proc.stdout
    assert proc.stderr.strip() == "", proc.stderr


def test_preflight_refuses_a_peer_that_is_not_an_address():
    """A malformed --admin-ip means the operator ends the run with nothing of
    their own allowlisted. Preflight is where that is still cheap to fix, so it
    says so rather than printing the garbage as though it were an address."""
    proc = run_bash("source deploy/lib/common.sh\n"
                    'ADMIN_IP="not-an-address"\n' + _preflight_peer_block() + "\n")
    assert proc.returncode == 0, proc.stderr
    assert "not-an-address" in proc.stderr, proc.stderr
    assert "NO allowlisted address" in proc.stderr, proc.stderr
    assert "allowlist_v4" not in proc.stdout and "allowlist_v6" not in proc.stdout


def test_preflight_still_says_when_it_has_no_address_at_all():
    """The pre-existing path: no --admin-ip, no SSH_CLIENT because sudo scrubbed
    it. That warning is what tells the operator to pass --admin-ip, and the new
    family branch must not have swallowed it."""
    proc = run_bash("source deploy/lib/common.sh\nunset SSH_CLIENT SSH_CONNECTION\n"
                    'ADMIN_IP=""\nSENTINEL_ADMIN_IP=""\n' + _preflight_peer_block() + "\n")
    assert proc.returncode == 0, proc.stderr
    assert "cannot determine your admin address" in proc.stderr, proc.stderr


# ---------------------------------------------------------------------------
# smoke-test.sh: the report that runs AFTER the install
# ---------------------------------------------------------------------------
# The firewall section is top-level code that talks to a server over ssh, so it
# cannot be run here as written. It is cut out and run with `r` — the one
# function that reaches the host — replaced by a table of canned answers. That
# is deliberately not a text search over the file: a grep for "allowlist_v6"
# would pass on a script that merely mentions it in a comment, and this
# repository has already shipped a check that grepped for a pattern nothing ever
# produced and therefore reported "nothing wrong" forever.

def _shell_function(path: Path, name: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", text, re.S | re.M)
    assert match, f"{name}() not found in {path.name}"
    return match.group(0)


def _smoke_firewall_block() -> str:
    """The firewall checks, cut out of the shipped scripts/smoke-test.sh.

    Both anchors are asserted: a cut that silently came back empty would make
    every assertion below pass against nothing.
    """
    text = SMOKE_TEST_SH.read_text(encoding="utf-8")
    start = "if r \"sudo nft list table inet sentinel\" | grep -q 'table inet sentinel'; then"
    assert start in text, "smoke-test.sh no longer opens the firewall section the way this test cuts"
    block = text.split(start, 1)[1]
    end = block.index('\nsect "Dashboard"')
    assert end > 0
    return start + block[:end]


SMOKE_HARNESS = r"""
set -euo pipefail

pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
sect() { :; }

# `ip` on the far side of ssh, for HOST_V6_MODE=exec. IP_MODE=fails is the case
# the reporting used to get wrong: the binary is there, it runs, and it exits
# non-zero — no IPv6 in the kernel, or a container without the capability.
ip() {
    case "${IP_MODE:-ok}" in
        fails) return 1 ;;
        *)     printf '%s\n' "${IP_LINES:-}" ;;
    esac
}

# The one function that reaches the server. Every answer below is a canned
# string chosen by an environment variable, so a test can put the host in a
# state — an empty allowlist_v6, a peer that is not in any set, an nft that does
# not understand `get element` — that cannot be produced on this machine.
#
# R_FAIL_MATCH is the FAILURE of the runner itself, and it is a separate thing
# from every canned answer below: ssh timing out, the network dropping, the host
# refusing the key. The real `r` sends stderr to /dev/null, so what a caller sees
# is empty output and a non-zero status — which is indistinguishable from a
# successful command that printed nothing unless the caller looks. Two `?`
# branches in this script had no test at all until this knob existed, and both
# of them collapse into "empty" or "no" when they are wrong, i.e. into a green
# or a red report about something nobody looked at.
r() {
    local cmd="$*" s a
    if [[ -n "${R_FAIL_MATCH:-}" && "$cmd" == *"${R_FAIL_MATCH}"* ]]; then
        return 1
    fi
    case "$cmd" in
        *"nft get element"*)
            s="$(printf '%s' "$cmd" | sed -n 's/.*inet sentinel \([a-z0-9_]*\) .*/\1/p')"
            a="$(printf '%s' "$cmd" | sed -n 's/.*{ \([^}]*\) }.*/\1/p')"
            a="${a%"${a##*[![:space:]]}"}"
            if [[ -n "${GET_BROKEN:-}" ]]; then
                # An nft that does not know the subcommand, or a sudo that said
                # no: an answer that is not "absent" and must not be read as one.
                printf 'Error: syntax error, unexpected get\n'
                return 1
            fi
            # The SET does not exist. nft 1.0.9 says this, and it contains the
            # same words as the element-not-found answer below — which is how a
            # broken table read as "you are not in the allowlist".
            #
            # GET_MISSING_SET_FOR names ONE set:address pair, because the whole
            # point is to reach this wording with the calibration still working.
            # GET_MISSING_SET applies to everything, which is what a genuinely
            # absent set looks like — and then the calibration cannot confirm
            # anything either, so the two knobs test different halves.
            if [[ -n "${GET_MISSING_SET:-}" ]] \
               || [[ " ${GET_MISSING_SET_FOR:-} " == *" ${s}:${a} "* ]]; then
                printf "Error: No such file or directory; did you mean set %s in table inet sentinel ?\n" "$s"
                return 1
            fi
            if [[ " ${GET_YES:-} " == *" ${s}:${a} "* ]]; then
                printf 'table inet sentinel {\n\tset %s {\n\t\telements = { %s }\n\t}\n}\n' "$s" "$a"
                return 0
            fi
            # The element is not in the set. The full phrase matters: only this
            # one means "not there".
            printf 'Error: Could not process rule: No such file or directory\n'
            return 1
            ;;
        *"list table inet sentinel"*)
            printf 'table inet sentinel {\n}\n' ;;
        *"list chain inet sentinel input"*)
            printf 'chain input { type filter hook input priority filter; policy accept; }\n' ;;
        *"list set inet sentinel allowlist_v4"*)
            printf '%s\n' "${SET_V4:-table inet sentinel { set allowlist_v4 { elements = { 127.0.0.0/8, 10.0.0.0/8 } } }}" ;;
        *"list set inet sentinel allowlist_v6"*)
            printf '%s\n' "${SET_V6:-table inet sentinel { set allowlist_v6 { elements = { ::1, fc00::/7 } } }}" ;;
        *"list set inet sentinel blocklist_v4"*)
            printf 'table inet sentinel {\n\tset blocklist_v4 {\n\t}\n}\n' ;;
        *"list set inet sentinel blocklist_v6"*)
            printf 'table inet sentinel {\n\tset blocklist_v6 {\n\t}\n}\n' ;;
        *SSH_CONNECTION*)
            printf '%s\n' "${PEER_LINE-198.51.100.4 51234 203.0.113.10 22}" ;;
        *"ip -6 -o addr show"*)
            case "${HOST_V6_MODE:-none}" in
                broken) printf '?\n' ;;
                none)   : ;;
                # The command the script sends to the server, RUN HERE, with
                # `ip` replaced. Everything the script decides about the host
                # addresses happens on the far side of ssh, so a harness that
                # only returns canned answers exercises none of it — and the
                # defect being fixed was exactly there: `ip … | awk | cut | sort
                # || echo '?'` takes its status from `sort`, so an `ip` that
                # exists and fails produced an empty answer and a zero status,
                # i.e. "this host has no IPv6", about a host nobody looked at.
                #
                # `set +e +u +o pipefail` FIRST, and it is not decoration. ssh
                # runs the command in a fresh login shell with none of those
                # options; this harness runs under `set -euo pipefail`, and
                # pipefail alone makes `ip | sed | sort` return the failure that
                # the defect is about — so the broken pipeline passed this test
                # until the subshell was made to look like the server.
                exec)   ( set +e +u +o pipefail; eval "$cmd" ) ;;
                *)      printf '%s\n' "${HOST_V6_ADDRS:-}" ;;
            esac ;;
        *"getent ahostsv4"*) printf '%s\n' "${GETENT4-192.0.2.20}" ;;
        *"getent ahostsv6"*) printf '%s\n' "${GETENT6-2001:db8:f::20}" ;;
    esac
    return 0
}

__FUNCTIONS__

__BLOCK__
"""


def run_smoke_firewall(**env: str) -> subprocess.CompletedProcess:
    functions = "\n".join(
        _shell_function(SMOKE_TEST_SH, name)
        for name in ("count_set_elements", "set_has_address", "check_in_set")
    )
    script = (SMOKE_HARNESS
              .replace("__FUNCTIONS__", functions)
              .replace("__BLOCK__", _smoke_firewall_block()))
    proc = run_bash(script, **env)
    assert proc.returncode == 0, f"the firewall section failed:\n{proc.stdout}\n{proc.stderr}"
    return proc


def test_the_smoke_test_counts_both_allowlist_sets():
    """The check that would have caught this bug on the host and did not.

    It counted `allowlist_v4` only, so an operator reachable solely over IPv6
    read "allowlist has 9 entries" from a report that had never looked at the
    set which could hold their address. An empty allowlist_v6 has to be a
    FAILURE with the set named, not a number about a different family.
    """
    out = run_smoke_firewall(
        SET_V6="table inet sentinel { set allowlist_v6 { type ipv6_addr } }",
    ).stdout
    assert re.search(r"^FAIL allowlist_v6 is EMPTY", out, re.M), out
    assert re.search(r"^PASS allowlist_v4 has 2 entries", out, re.M), out


def test_an_empty_set_is_counted_as_zero_and_not_as_garbage():
    """`grep -c .` prints "0" AND exits 1 on empty input, so `|| printf '0'`
    produced "0\\n0" — a value `(( ))` cannot read. It reached the right branch
    by accident, with a shell syntax error on stderr, and printed the garbage
    verbatim in the blocklist line next to it.
    """
    proc = run_smoke_firewall(
        SET_V6="table inet sentinel { set allowlist_v6 { type ipv6_addr } }")
    assert "0\n0" not in proc.stdout, proc.stdout
    assert "syntax error" not in proc.stderr, proc.stderr
    assert re.search(r"^    blocklist: 0 IPv4, 0 IPv6$", proc.stdout, re.M), proc.stdout


def test_the_smoke_test_checks_your_own_address_in_the_set_of_its_family():
    """Nothing in this report used to look at the operator's own address at all.
    smoke-test.sh takes no --admin-ip, but the peer of the connection it is
    running over IS that address, in the family actually in use — and it is the
    one entry whose absence means the next auto-block can lock the operator out.
    """
    out = run_smoke_firewall(
        PEER_LINE="2001:db8::1 51234 2001:db8:abc::5 22",
        GET_YES="allowlist_v4:127.0.0.1 allowlist_v6:::1 allowlist_v6:2001:db8::1",
    ).stdout
    assert re.search(r"^PASS adresa ta \(2001:db8::1\) e în allowlist_v6", out, re.M), out

    # And the other way round: present in v4, absent from the set of its family.
    out = run_smoke_firewall(
        PEER_LINE="2001:db8::1 51234 2001:db8:abc::5 22",
        GET_YES="allowlist_v4:127.0.0.1 allowlist_v6:::1",
    ).stdout
    assert re.search(r"^WARN adresa ta \(2001:db8::1\) NU e în allowlist_v6", out, re.M), out


def test_membership_is_asked_of_the_kernel_so_a_covering_range_still_counts():
    """The operator administers from 192.168.1.50 and the allowlist holds
    192.168.0.0/16. A grep over the set listing finds no such text and would
    warn — on every run, on every operator inside a private range or inside one
    of their own extra_allowlist prefixes. A warning that is wrong every time is
    one that gets switched off, taking the true one with it.
    """
    out = run_smoke_firewall(
        PEER_LINE="192.168.1.50 51234 203.0.113.10 22",
        # The kernel answers with the INTERVAL that covers the address, which is
        # the text a grep would have been looking for and never found.
        GET_YES="allowlist_v4:192.168.1.50 allowlist_v4:127.0.0.1 allowlist_v6:::1",
    ).stdout
    assert re.search(r"^PASS adresa ta \(192\.168\.1\.50\) e în allowlist_v4", out, re.M), out


def test_a_membership_query_that_cannot_answer_reports_nothing_rather_than_ok():
    """If `nft get element` is unknown to this nft, or sudo refuses it, then no
    address below has been checked. Reporting those as present would be a green
    report nobody produced; reporting them as absent would send the operator to
    fix an allowlist that is fine.

    So the query is calibrated first against an address the installer ALWAYS
    puts in the set, and if that comes back anything but "present" the checks
    are skipped and said to be skipped.
    """
    proc = run_smoke_firewall(GET_BROKEN="1",
                              PEER_LINE="203.0.113.10 51234 203.0.113.11 22")
    out = proc.stdout
    assert re.search(r"^WARN nu pot interoga apartenența la seturi", out, re.M), out
    assert "SĂRITE" in out, out
    # Nothing was claimed about any individual address, either way: no PASS and
    # no WARN naming one.
    assert "adresa ta" not in out, out
    assert "api.telegram.org" not in out, out
    assert "adresa proprie a gazdei" not in out, out


def test_a_set_that_could_not_be_read_is_unknown_not_empty():
    """"I could not read allowlist_v6" and "allowlist_v6 is empty" are different
    facts, and the second one is a FAIL with a sentence about being unprotected.

    Reported as empty, an ssh that timed out sends the operator to repair an
    allowlist that is fine — and once a smoke test has cried wolf, the run where
    the set really is empty is the one nobody acts on.
    """
    proc = run_smoke_firewall(R_FAIL_MATCH="list set inet sentinel allowlist_v6")
    out = proc.stdout
    assert re.search(r"^WARN nu am putut citi allowlist_v6", out, re.M), out
    assert "allowlist_v6 is EMPTY" not in out, out
    assert not re.search(r"^FAIL", out, re.M), out
    # The other family was read and is still reported, so this is not a global
    # bail-out dressed up as a warning.
    assert re.search(r"^PASS allowlist_v4 has 2 entries", out, re.M), out


def test_an_answer_that_is_not_a_set_listing_is_unknown_not_empty():
    """A sudo asking for a password, a truncated ssh session, an error message —
    none of them is a set listing, and after the `sed` all of them look exactly
    like an empty set, because an empty set really does have no `elements = {`
    line.

    Empty is reported as a FAIL with a sentence about nothing protecting the
    operator. Sending them chasing that on a report they could not read is how a
    smoke test stops being read at all.
    """
    out = run_smoke_firewall(
        SET_V6="[sudo] password for deploy:",
    ).stdout
    assert re.search(r"^WARN nu am putut citi allowlist_v6", out, re.M), out
    assert "allowlist_v6 is EMPTY" not in out, out

    # A genuinely empty set still counts as empty: the header is there, the
    # elements are not.
    out = run_smoke_firewall(
        SET_V6="table inet sentinel {\n\tset allowlist_v6 {\n\t\ttype ipv6_addr\n\t}\n}",
    ).stdout
    assert re.search(r"^FAIL allowlist_v6 is EMPTY", out, re.M), out


def test_a_membership_query_that_could_not_run_is_unknown_not_absent():
    """The calibration passed, so `nft get element` works — and then THIS query
    did not come back.

    Reported as "not in the set" it is a warning about an address that may well
    be allowlisted, on a report the operator is meant to act on. Reported as
    "yes" it is worse. The only honest answer is that the question was not
    answered.
    """
    out = run_smoke_firewall(
        PEER_LINE="198.51.100.4 51234 203.0.113.10 22",
        GET_YES="allowlist_v4:127.0.0.1 allowlist_v6:::1 allowlist_v4:198.51.100.4",
        R_FAIL_MATCH="{ 198.51.100.4 }",
    ).stdout
    assert re.search(r"^WARN adresa ta \(198\.51\.100\.4\).*necunoscut", out, re.M), out
    # Exactly one line mentions the address, and it is that one: neither a
    # "NU e în" (which would be a false alarm) nor an "e în" (a false green).
    about_it = [line for line in out.splitlines() if "198.51.100.4" in line]
    assert len(about_it) == 1, about_it
    assert "necunoscut" in about_it[0], about_it


def test_a_missing_set_is_unknown_and_not_absence():
    """`nft get element` on a set that does not exist answers
    "Error: No such file or directory; did you mean set ..." — which shares its
    words with the element-not-found answer, "Error: Could not process rule: No
    such file or directory".

    Matched loosely, a table with no allowlist_v6 at all reported "you are NOT in
    allowlist_v6", which sends the operator to add an address to a set that does
    not exist while the real fault — a broken or half-loaded table — goes
    unmentioned.
    """
    # The calibration works, so the question is being asked and answered — and
    # THIS answer is the missing-set one. It has to come out as unknown.
    out = run_smoke_firewall(
        PEER_LINE="198.51.100.4 51234 203.0.113.10 22",
        GET_YES="allowlist_v4:127.0.0.1 allowlist_v6:::1",
        GET_MISSING_SET_FOR="allowlist_v4:198.51.100.4",
    ).stdout
    about_it = [line for line in out.splitlines() if "198.51.100.4" in line]
    assert len(about_it) == 1, about_it
    assert "nu am putut întreba allowlist_v4" in about_it[0], about_it
    assert "NU e în" not in about_it[0], about_it

    # And when the set is missing for EVERY query, the calibration cannot
    # confirm anything either: the checks are skipped, and nothing is claimed
    # about any address.
    out = run_smoke_firewall(GET_MISSING_SET="1",
                             PEER_LINE="203.0.113.10 51234 203.0.113.11 22").stdout
    assert re.search(r"^WARN nu pot interoga apartenența la seturi", out, re.M), out
    assert "NU e în" not in out, out

    # And the element-not-found wording still means exactly "no": it is the one
    # answer that is evidence of absence.
    out = run_smoke_firewall(
        PEER_LINE="203.0.113.10 51234 203.0.113.11 22",
        GET_YES="allowlist_v4:127.0.0.1 allowlist_v6:::1",
    ).stdout
    assert re.search(r"^WARN adresa ta \(203\.0\.113\.10\) NU e în allowlist_v4",
                     out, re.M), out


def test_a_family_whose_probe_failed_is_skipped_and_not_passed():
    """The calibration asks the kernel about an address the installer ALWAYS
    puts in the set — 127.0.0.1 in allowlist_v4, ::1 in allowlist_v6. If that
    comes back anything but "present", the question is not working for that
    family and no answer from it means anything.

    Per family, not globally: a v6 probe that fails must not silence the v4
    checks, or a report that could still say something useful says nothing.
    And it must not produce a PASS for the family it could not ask about — a
    green line nobody produced is the worst of the three outcomes.
    """
    out = run_smoke_firewall(
        PEER_LINE="203.0.113.10 51234 203.0.113.11 22",
        GET_YES=("allowlist_v4:127.0.0.1 allowlist_v4:203.0.113.10 "
                 "allowlist_v4:192.0.2.20"),
        HOST_V6_MODE="fixed", HOST_V6_ADDRS="2001:db8:abc::5",
    ).stdout
    assert re.search(r"^WARN nu pot interoga apartenența la seturi", out, re.M), out
    assert "v4=1, v6=0" in out, out
    assert "SĂRITE" in out, out

    # v4 still reports.
    assert re.search(r"^PASS adresa ta \(203\.0\.113\.10\) e în allowlist_v4", out, re.M), out
    # and no MEMBERSHIP verdict is given for the v6 set, in either direction.
    # (The element count for allowlist_v6 is a different check and still runs;
    # it reads the set, it does not ask the kernel about an address.)
    verdicts = [line for line in out.splitlines()
                if re.match(r"^(PASS|WARN) ", line) and "e în allowlist_v6" in line]
    assert verdicts == [], verdicts
    assert "adresa proprie a gazdei" not in out, out


def test_an_ip_that_exists_and_fails_is_unknown_not_no_ipv6():
    """`ip -6 … | awk | cut | sort -u || echo '?'` cannot ever print "?": in a
    pipeline `||` looks at the LAST command, which is `sort`, and `sort` on an
    empty pipe succeeds.

    So an `ip` that exists and exits non-zero — no IPv6 in the kernel, a
    container without the capability — produced empty output and a zero status,
    which this script reads as "the host has no global IPv6 address": a
    comfortable sentence about a host nobody managed to look at.

    The command is run here, with `ip` replaced, rather than having its answer
    canned: the logic under test lives inside the string sent over ssh, and a
    canned answer would test the harness.
    """
    out = run_smoke_firewall(
        HOST_V6_MODE="exec", IP_MODE="fails",
        GET_YES="allowlist_v4:127.0.0.1 allowlist_v6:::1",
    ).stdout
    assert re.search(r"^WARN nu am putut afla adresele IPv6 globale", out, re.M), out
    assert "gazda nu are adresă IPv6 globală" not in out, out


def test_the_addresses_ip_does_report_are_checked_one_by_one():
    """The other side of the same command: when `ip` works, its output has to be
    turned into addresses. A parser that returned nothing would look exactly
    like a host without IPv6, which is the state that is supposed to be quiet —
    so it would never be noticed.
    """
    lines = ("2: eth0    inet6 2001:db8:abc::5/64 scope global \\       valid_lft forever\n"
             "2: eth0    inet6 2001:db8:abc::6/64 scope global \\       valid_lft forever")
    out = run_smoke_firewall(
        HOST_V6_MODE="exec", IP_MODE="ok", IP_LINES=lines,
        GET_YES=("allowlist_v4:127.0.0.1 allowlist_v6:::1 "
                 "allowlist_v6:2001:db8:abc::5"),
    ).stdout
    assert re.search(r"^PASS adresa proprie a gazdei \(2001:db8:abc::5\) e în allowlist_v6",
                     out, re.M), out
    assert re.search(r"^WARN adresa proprie a gazdei \(2001:db8:abc::6\) NU e în allowlist_v6",
                     out, re.M), out


def test_a_host_without_global_ipv6_is_stated_not_warned_about():
    """Most hosts have no global IPv6 address, and that is not a fault: the v6
    set legitimately holds only loopback, ULA and link-local. A warning here
    would fire on every deploy on every such host, and a warning that always
    fires is one the operator stops reading.
    """
    out = run_smoke_firewall(
        HOST_V6_MODE="none",
        GET_YES="allowlist_v4:127.0.0.1 allowlist_v6:::1 allowlist_v4:198.51.100.4",
        GETENT6="",
    ).stdout
    assert re.search(r"^    gazda nu are adresă IPv6 globală", out, re.M), out
    # Stated on an ordinary informational line, not as a WARN — and no other
    # warning about the host's addresses either.
    assert not re.search(r"^WARN .*IPv6", out, re.M), out
    assert "adresa proprie a gazdei" not in out, out


def test_an_unreadable_ipv6_address_list_is_unknown_not_absent():
    """"`ip` did not answer" and "this host has no IPv6" are different facts.
    Collapsing them would print a comfortable sentence about a host nobody
    looked at.
    """
    out = run_smoke_firewall(
        HOST_V6_MODE="broken",
        GET_YES="allowlist_v4:127.0.0.1 allowlist_v6:::1",
    ).stdout
    assert re.search(r"^WARN nu am putut afla adresele IPv6 globale", out, re.M), out
    assert "gazda nu are adresă IPv6 globală" not in out, out


def test_the_api_endpoints_are_checked_on_both_families():
    """Blocking Telegram removes the only channel Sentinel can speak on. The
    check resolved `ahostsv4` only, so the IPv6 address the name answers with
    could be missing from allowlist_v6 with nothing on screen to say so — and on
    both production hosts `getent ahostsv6` does answer, with a native address.
    """
    out = run_smoke_firewall(
        GETENT4="192.0.2.20", GETENT6="2001:db8:f::20",
        GET_YES=("allowlist_v4:127.0.0.1 allowlist_v6:::1 "
                 "allowlist_v4:192.0.2.20 allowlist_v4:198.51.100.4"),
    ).stdout
    assert "PASS api.telegram.org (IPv4) (192.0.2.20) e în allowlist_v4" in out, out
    assert "WARN api.telegram.org (IPv6) (2001:db8:f::20) NU e în allowlist_v6" in out, out
    assert "PASS api.anthropic.com (IPv4) (192.0.2.20) e în allowlist_v4" in out, out
