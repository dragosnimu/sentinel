"""Every function a committed shell script calls must be defined in something
committed alongside it.

This is `tests/unit/test_module_imports.py` for shell. That test exists because
a commit can reference a Python symbol whose definition never left the working
tree; this one exists because the same thing happens in bash, and bash hides it
better. Three shipped instances:

  41b7723  `sentinel/patch/{backup,checks,runner}.py` imported
           `TIMEOUT_MARGIN_S`, uncommitted. `sentinel-maintenance` exited
           1/FAILURE hourly on both hosts for 24 h; backups stopped.
  15ec851  `ingest_service.py` called `nginx_tail.at_end(...)`, uncommitted.
           Ingestion died on both hosts — zero new events, 1445 errors, the
           suricata collector stuck with 3 MB unread, the detect loop stopped.
  21 Sep   `deploy/install.sh` called `migrate_legacy_state_markers` and
           `ensure_state_markers_dir`, both defined only in an uncommitted
           `deploy/lib/common.sh`. The deploy died on the Ubuntu host with
           `line 5586: migrate_legacy_state_markers: command not found`,
           seconds after the operator confirmed it. Nothing had been changed
           on the host yet only because of where it happened to die.

Neither gate that existed could see the third one:

  * the full suite in a clean clone at that commit reported 5276 passed. No
    test executes the installer end to end — nothing calls `main()`, and a
    step-level test only reads the text around the step it cares about;
  * `bash -n deploy/install.sh` returned 0. Bash resolves a command name when
    it RUNS the line, not when it parses the file, so a call to a function
    that does not exist anywhere is perfectly valid syntax. `bash -n` would
    have said the same thing about a script consisting of one call to a
    function nobody ever wrote.

So the fact this test checks is not "the file parses" and not "the step ran in
a test". It is: for every word this script would execute as a command, either
something committed defines it as a function, or bash provides it, or it is a
binary on the declared host inventory below. Nothing else resolves.

## Committed content, never the working tree

Every path below is read with `git show HEAD:<path>`. The working tree always
looks fine — that is the entire defect. On 21 September the tree had both
functions; `git` did not. Line numbers in a failure message are therefore
lines of the COMMITTED file, which is not necessarily the line you see in your
editor.

## Where the line is drawn on "a call"

Reported as a call: a plain word in command position — first word of a simple
command, including after `|`, `&&`, `||`, `;`, `&`, newline, inside `$( )`,
backticks, `<( )`, a subshell, an `if`/`while`/`until` condition, a `case`
body, a function body — plus the first argument of `trap`, which bash runs as
code, and the substitutions inside an UNQUOTED heredoc body, which bash runs
where they stand.

Deliberately NOT reported, each one a place this check is blind:

  * anything inside single or double quotes. `ssh host "systemctl restart x"`
    and `bash -c 'do_thing'` run somewhere else or later; parsing them would
    flood this test with names that are not meant to resolve here. A local
    function invoked only from inside a quoted string is invisible to this
    check — `trap` is the one exception, because its argument is shell code
    run in this shell.
  * `eval "$INSTALL_ENV"` (scripts/wizard.sh) and any other construct whose
    command name is built at runtime.
  * a command word that is an expansion — `"$py" -V`, `"${SUDO[@]}" cmd`.
    Nothing static can say what those are.
  * arguments of wrappers: `sudo foo`, `timeout 12 foo`, `xargs foo`,
    `runuser -u x -- foo`. Today every such argument in the corpus is an
    external binary; a function passed to one would not be checked.
  * bare words in a heredoc body, and everything in a heredoc whose delimiter
    is quoted (`<<'EOF'`, `<<"EOF"`, or a backslash before it) — that body
    really is data.
    An UNQUOTED `<<EOF` is not: bash expands `$( )` and backticks in it as it
    reads the line, so those ARE scanned. The first version of this file
    called every heredoc body "data", which was wrong, and a blind spot
    described wrongly is worse than one described at all.
  * words inside comments.
  * `case` patterns (`--domain)` is not a call) and array literal elements
    (`local -a order=(sentinel-web …)` names units, not commands) — but the
    scanner has to come back OUT of both, which is what
    `test_the_scanner_reads_each_script_as_code_end_to_end` measures.

Under-matching in those places means this test can miss a defect. It cannot
produce a false alarm from them, which is the trade taken on purpose: a test
that cries wolf about `ssh` payloads gets deleted, and a deleted test catches
nothing at all.

Two constructs would go the other way and cry wolf. Neither occurs in the
corpus; both were found by review, not by this test failing:

  * `coproc NAME { … }` — NAME is not a command, and would be reported as an
    undefined one.
  * a function defined through `eval` and called normally. Nothing static
    can see that definition, so the call looks unresolved.

If either ever appears, the failure names the line and the fix is to teach
the scanner, not to widen EXTERNAL_COMMANDS.

## The other way this file can lie

Everything above is about what the scanner FINDS. The failure that actually
got through review was about where it LOOKED: an apostrophe in a comment
inside `ASSETS=( … )` in scripts/vendor-assets.sh opened a quoted run that
closed thirteen lines later, and 71% of that file was never read as code —
six commands seen out of forty-one, an undefined function injected past line
55 reported clean, and every test here green. A lexer that loses the thread
does not crash; it reads to the last byte and finds nothing.

So a second, line-oriented model of the same text (`_flat_line_model`) says
which lines bash would be reading as code, and the scanner has to have been
there. The two share no mechanism, which is the only reason one can catch the
other.

That second model answers three ways, not two — `certain`, `unknown`, and
nothing at all for blank lines — and only `certain` is compared. Its first
version answered two, and inside a week it had produced both of the failures
that shape has to produce: a word list it did not recognise turned correct
shell RED (four more options in an array that already ships), and a heredoc
opener quoted inside a string made it go QUIET over 497 lines. See the
comment above `_flat_line_model` for why monotone is the answer to both and
what it costs.
"""

from __future__ import annotations

import bisect
import posixpath
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# What bash itself provides. Absent from these two sets, a word has to be
# either a function defined in committed source or a binary on the host.
# ---------------------------------------------------------------------------

BASH_KEYWORDS = {
    "if", "then", "elif", "else", "fi",
    "while", "until", "do", "done",
    "for", "select", "in",
    "case", "esac",
    "function", "time", "coproc",
    "{", "}", "!", "[[", "]]",
}

BASH_BUILTINS = {
    ":", ".", "source", "[", "alias", "bg", "bind", "break", "builtin",
    "caller", "cd", "command", "compgen", "complete", "compopt", "continue",
    "declare", "dirs", "disown", "echo", "enable", "eval", "exec", "exit",
    "export", "false", "fc", "fg", "getopts", "hash", "help", "history",
    "jobs", "kill", "let", "local", "logout", "mapfile", "popd", "printf",
    "pushd", "pwd", "read", "readarray", "readonly", "return", "set", "shift",
    "shopt", "suspend", "test", "times", "trap", "true", "type", "typeset",
    "ulimit", "umask", "unalias", "unset", "wait",
}

# ---------------------------------------------------------------------------
# Binaries the host provides. This is an inventory, not a mute button.
#
# `command -v` is not usable here: the PATH of this Windows sandbox has
# nothing to do with the PATH of an AlmaLinux or Ubuntu host, so asking it
# would answer a different question and answer it wrongly in both directions.
# An entry here is a claim that the name is an executable the deploy expects
# to find on the target, and that claim is reviewed when it is added.
#
# Adding a name here to make this test green is the wrong repair for the
# failure it exists to catch: if the missing word is a shell function, the fix
# is to COMMIT the file that defines it.
# `test_no_function_names_hidden_as_binaries` below blocks the obvious form of
# that mistake.
# ---------------------------------------------------------------------------

EXTERNAL_COMMANDS = {
    # coreutils and friends — present on any host the installer supports
    "awk", "base64", "basename", "cat", "chmod", "chown", "cmp", "comm", "cp",
    "cut", "date", "df", "dirname", "du", "find", "getent", "grep", "head", "id",
    "install", "ln", "mkdir", "mktemp", "mv", "od", "readlink", "rm", "sed",
    "seq", "sha256sum", "sleep", "sort", "stat", "tail", "tar", "timeout",
    "touch", "tr", "uniq", "unzip", "wc",
    # accounts, privilege, ACLs
    "groupadd", "runuser", "setfacl", "sudo", "useradd", "usermod", "visudo",
    # package managers, both families (deploy/lib/distro.sh)
    "apt-get", "dnf", "dpkg", "dpkg-query", "rpm",
    # systemd and the journal
    "journalctl", "systemctl", "systemd-tmpfiles",
    # network, firewall, TLS
    "certbot", "curl", "ip", "nft", "openssl", "ss", "ufw",
    # the services Sentinel installs and configures
    "docker", "logrotate", "nginx", "pgrep", "postgresql-setup", "psql",
    "pg_lsclusters", "suricata", "suricata-update",
    # audit
    "auditctl", "augenrules",
    # interpreters and the operator-side tooling (scripts/ runs on Windows or
    # on the operator's shell, not on the monitored host)
    "bash", "git", "hostname", "jq", "python3", "scp", "ssh",
    # SELinux (RHEL family only; guarded at the call site)
    "setsebool",
}

# Every function in this repository's shell is snake_case, so a snake_case
# word that resolves to nothing is overwhelmingly likely to be a function
# whose definition did not get committed — exactly the bug. Silencing one by
# adding it to EXTERNAL_COMMANDS would turn this test back into the thing it
# replaces, so the two real binaries that happen to carry an underscore are
# named here and nothing else may.
UNDERSCORED_BINARIES = {
    "pg_lsclusters",   # Debian/Ubuntu postgresql-common
    "postgresql-setup",  # RHEL family; hyphen, listed for symmetry
}

# ---------------------------------------------------------------------------
# `source` targets that cannot be followed, each read once and confirmed to be
# a KEY=value data file rather than shell that could define a function. A
# source this check cannot resolve is NOT assumed harmless: an undeclared one
# fails `test_every_source_directive_is_followed_or_declared`, because "I
# could not see what that pulls in" and "that pulls in nothing" are different
# answers and only one of them is safe to act on.
# ---------------------------------------------------------------------------

OPAQUE_SOURCES: dict[tuple[str, str], str] = {
    ("deploy/lib/distro.sh", "/etc/os-release"):
        "the host's own os-release; KEY=value only, and not ours to read from git",
    ("deploy/install.sh", '"$env_file"'):
        "${STATE_MARKERS}/preflight.env, written by preflight.sh as KEY=value "
        "and sourced back; install.sh refuses it unless it is root-owned 0700 "
        "(assert_root_owned_state_file) precisely because it is executed",
    ("scripts/wizard.sh", '"$CONFIG_FILE"'):
        "the operator's saved wizard answers (--config), KEY=value",
}

# The ONLY variables `_resolve_source_target` will expand, and the committed
# assignment each one must still carry. One table for both jobs on purpose: an
# expansion the resolver performs but nothing verifies is resolution trusting
# a value it never read, which is the same class of mistake as trusting a
# filesystem or a configuration. `${SRC_ROOT}` used to be expanded here with
# no entry — and in scripts/lib/check-line-endings.sh its committed value is
# `SRC_ROOT="${2:-}"`, whatever the caller passed. Nothing sources through it
# today; it is not expanded any more either, so if anything ever does, the
# target comes out unresolvable and has to be declared rather than guessed.
#
# `%(dir)s` is the directory of the script being resolved.
PATH_VARIABLES: dict[str, tuple[str, str]] = {
    "SCRIPT_DIR": (
        "%(dir)s",
        r'SCRIPT_DIR="\$\(cd "\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)" && pwd\)"'),
    "REPO_ROOT": (
        ".",
        r'REPO_ROOT="\$\(cd "\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)/\.\." && pwd\)"'),
}

#: `$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)` written out inline.
_SCRIPT_DIR_INLINE = '$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)'


# ===========================================================================
# The scanner
# ===========================================================================

_WORD_END = set(" \t\n;&|()<>")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")
_FUNCTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


@dataclass
class Command:
    """A word bash would look up as a command, plus its unquoted arguments."""

    name: str
    offset: int
    args: list[str] = field(default_factory=list)
    #: raw, still-quoted text of each argument, for `trap`
    raw_args: list[str] = field(default_factory=list)


@dataclass
class ScriptScan:
    defs: dict[str, int] = field(default_factory=dict)          # name -> offset
    commands: list[Command] = field(default_factory=list)
    sources: list[tuple[str, int]] = field(default_factory=list)  # raw target, offset
    #: Lines the scanner read AS CODE — where it was looking for a command
    #: rather than consuming a string, a comment, a heredoc body or a word
    #: list. This is the only quantity that shows a lexer which has lost the
    #: thread: such a scanner still runs to the last byte of the file, it just
    #: believes almost none of it is code. See
    #: `test_the_scanner_reads_each_script_as_code_end_to_end`.
    code_lines: set[int] = field(default_factory=set)


class _Scanner:
    """A bash lexer that answers one question: which words are commands.

    Offsets only. Line numbers are derived at the end by counting newlines
    before the offset — a line counter maintained as the scan advances has to
    be right in every skip path (heredoc bodies, comments, `${…}`, quoted
    spans), and being wrong there produces a failure message pointing at an
    innocent line, which is worse than no message.
    """

    def __init__(self, text: str) -> None:
        self.t = text
        self.n = len(text)
        self.i = 0
        self.out = ScriptScan()
        self._heredocs: list[tuple[str, bool, bool]] = []   # delim, strip, expands
        #: Inside `…`, a backtick ENDS the current word instead of opening a
        #: nested substitution. Without this, x=`missing_one` scanned as one
        #: unresolvable word and the call disappeared.
        self._backticks = 0
        #: every offset the command-level loop looked at, for `code_lines`
        self._code_offsets: list[int] = []

    # -- skipping constructs -------------------------------------------------

    def _newline(self) -> None:
        self.i += 1
        while self._heredocs:
            delim, strip, expands = self._heredocs.pop(0)
            self._skip_heredoc_body(delim, strip, expands)

    def _skip_heredoc_body(self, delim: str, strip: bool, expands: bool) -> None:
        """Consume a heredoc body; in an UNQUOTED one, run its substitutions.

        `cat <<EOF` with `$(missing_one)` in the body executes `missing_one`
        in this shell, right there — the body is a template, not data, and
        only `<<'EOF'` makes it data. Six bodies in the corpus expand
        something today (all `$(printf …)`), so nothing is missing now; the
        distinction is here because the docstring that called every heredoc
        body "data" was simply wrong, and a blind spot described incorrectly
        is worse than one described at all.
        """
        start = self.i
        body_end, after = start, self.n
        while body_end < self.n:
            end = self.t.find("\n", body_end)
            if end < 0:
                body_end, after = self.n, self.n
                break
            line = self.t[body_end:end]
            probe = line.lstrip("\t") if strip else line
            if probe.rstrip("\r") == delim:
                after = end + 1
                break
            body_end = end + 1
        else:
            after = self.n

        if expands:
            j = start
            while j < body_end:
                c = self.t[j]
                if c == "\\":
                    j += 2
                    continue
                if self.t.startswith("$((", j):
                    j += 3
                    continue
                if self.t.startswith("$(", j):
                    self.i = j + 2
                    self._parse(end=")")
                    j = max(self.i, j + 2)
                    continue
                if c == "`":
                    self.i = j + 1
                    self._parse(end="`")
                    j = max(self.i, j + 1)
                    continue
                j += 1
        self.i = after

    def _skip_single_quoted(self) -> None:
        self.i += 1
        while self.i < self.n and self.t[self.i] != "'":
            self.i += 1
        self.i += 1

    def _skip_dollar_quoted(self) -> None:
        self.i += 2
        while self.i < self.n:
            c = self.t[self.i]
            if c == "\\":
                self.i += 2
                continue
            self.i += 1
            if c == "'":
                return

    def _skip_double_quoted(self) -> None:
        # Command substitution inside double quotes still runs commands, so it
        # is scanned; everything else in here is text.
        self.i += 1
        while self.i < self.n:
            c = self.t[self.i]
            if c == "\\":
                self.i += 2
                continue
            if c == '"':
                self.i += 1
                return
            if self.t.startswith("$((", self.i):
                self._skip_arithmetic()
                continue
            if self.t.startswith("$(", self.i):
                self.i += 2
                self._parse(end=")")
                continue
            if c == "`":
                self.i += 1
                self._parse(end="`")
                continue
            if self.t.startswith("${", self.i):
                self._skip_braced_expansion()
                continue
            self.i += 1

    def _skip_braced_expansion(self) -> None:
        self.i += 2
        depth = 1
        while self.i < self.n and depth:
            c = self.t[self.i]
            if c == "\\":
                self.i += 2
                continue
            if c == "'":
                self._skip_single_quoted()
                continue
            if c == '"':
                self._skip_double_quoted()
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            self.i += 1

    def _skip_arithmetic(self) -> None:
        self.i += 3 if self.t[self.i] == "$" else 2
        depth = 1
        while self.i < self.n and depth:
            if self.t.startswith("((", self.i):
                depth += 1
                self.i += 2
                continue
            if self.t.startswith("))", self.i):
                depth -= 1
                self.i += 2
                continue
            c = self.t[self.i]
            if c == "'":
                self._skip_single_quoted()
                continue
            if c == '"':
                self._skip_double_quoted()
                continue
            self.i += 1

    def _skip_array_literal(self) -> None:
        # `local -a order=(sentinel-web sentinel-ai)` — elements are words, not
        # commands. Treating this as a subshell reported `sentinel-web` as an
        # undefined function while the scanner was being built.
        #
        # A word list takes comments like any other list, and that is not a
        # detail: scripts/vendor-assets.sh documents every asset in a comment
        # INSIDE `ASSETS=( … )`, one of which reads "Chart.js's ~200 KB". With
        # no comment rule here, that apostrophe opened a quoted run that shut
        # thirteen lines later and the scan lost 71% of the file — six
        # commands seen out of forty-one, and an undefined function injected
        # anywhere past line 55 came back clean.
        self.i += 1
        depth = 1
        while self.i < self.n and depth:
            c = self.t[self.i]
            if c == "#" and self.t[self.i - 1] in " \t\n(":
                nl = self.t.find("\n", self.i)
                self.i = nl if nl >= 0 else self.n
                continue
            if c == "'":
                self._skip_single_quoted()
                continue
            if c == '"':
                self._skip_double_quoted()
                continue
            if c == "\\":
                self.i += 2
                continue
            if self.t.startswith("$(", self.i):
                self.i += 2
                self._parse(end=")")
                continue
            if c == "`":
                self.i += 1
                self._parse(end="`")
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            self.i += 1

    def _read_word(self) -> tuple[str, bool, int]:
        """Return (raw text, unquoted, offset).

        `unquoted` is False as soon as any quote or expansion appears in the
        word: `"$py"` is a command name this check cannot resolve, and must
        not be reported as a missing function.
        """
        start = self.i
        unquoted = True
        while self.i < self.n:
            c = self.t[self.i]
            if c in _WORD_END:
                break
            if c == "\\":
                if self.i + 1 < self.n and self.t[self.i + 1] == "\n":
                    self.i += 2  # line continuation, the word keeps going
                    continue
                unquoted = False
                self.i += 2
                continue
            if c == "'":
                unquoted = False
                self._skip_single_quoted()
                continue
            if c == '"':
                unquoted = False
                self._skip_double_quoted()
                continue
            if c == "$":
                unquoted = False
                if self.t.startswith("$((", self.i):
                    self._skip_arithmetic()
                elif self.t.startswith("$(", self.i):
                    self.i += 2
                    self._parse(end=")")
                elif self.t.startswith("${", self.i):
                    self._skip_braced_expansion()
                elif self.t.startswith("$'", self.i):
                    self._skip_dollar_quoted()
                else:
                    self.i += 1
                continue
            if c == "`":
                if self._backticks:
                    break
                unquoted = False
                self.i += 1
                self._parse(end="`")
                continue
            self.i += 1
        return self.t[start:self.i], unquoted, start

    def _skip_blanks(self) -> None:
        while self.i < self.n and self.t[self.i] in " \t":
            self.i += 1

    def _read_redirection(self) -> None:
        if self.t.startswith("<<<", self.i):          # here-string: data
            self.i += 3
            self._skip_blanks()
            self._read_word()
            return
        if self.t.startswith("<<", self.i):           # heredoc
            self.i += 2
            strip = self.i < self.n and self.t[self.i] == "-"
            if strip:
                self.i += 1
            self._skip_blanks()
            raw, _, _ = self._read_word()
            # Any quoting ANYWHERE in the delimiter word turns expansion off
            # for the whole body — `<<'EOF'`, `<<"EOF"` and `<<\EOF` alike.
            expands = not any(ch in raw for ch in "'\"\\")
            self._heredocs.append((raw.replace("'", "").replace('"', "")
                                      .replace("\\", ""), strip, expands))
            return
        if self.t.startswith("<(", self.i) or self.t.startswith(">(", self.i):
            self.i += 2                               # process substitution
            self._parse(end=")")
            return
        while self.i < self.n and self.t[self.i] in "<>&":
            if self.t[self.i] == "&" and self.t[self.i - 1] not in "<>":
                break
            self.i += 1
        self._skip_blanks()
        if self.i < self.n and self.t[self.i] not in "\n;|&":
            self._read_word()                         # the redirection target

    # -- the command-position state machine ----------------------------------

    def _parse(self, end: str | None = None) -> None:
        if end == "`":
            self._backticks += 1
        try:
            self._parse_command_list(end)
        finally:
            if end == "`":
                self._backticks -= 1

    def _parse_command_list(self, end: str | None = None) -> None:
        cmd_pos = True
        subshells: list[str] = []
        case_state: list[str] = []      # "pattern" | "body"
        in_word_list = False            # between `for x` and `do`
        cond_depth = 0                  # inside [[ … ]]
        naming_function = False         # the word after `function`
        current: Command | None = None

        while self.i < self.n:
            c = self.t[self.i]
            self._code_offsets.append(self.i)

            if c in " \t":
                self.i += 1
                continue
            if c == "\\" and self.i + 1 < self.n and self.t[self.i + 1] == "\n":
                self.i += 2
                continue
            if c == "\n":
                self._newline()
                in_word_list = False
                current = None
                if not case_state or case_state[-1] != "pattern":
                    cmd_pos = True
                continue
            # `)` belongs in this set: it is a control operator, so `#` right
            # after it starts a word, and a word starting with `#` is a
            # comment. `( helper )# note don't` is valid shell that `bash -n`
            # accepts, and without the `)` this scanner reported a missing
            # command named `#`.
            if c == "#" and (self.i == 0 or self.t[self.i - 1] in " \t\n;&|()<>"):
                nl = self.t.find("\n", self.i)
                self.i = nl if nl >= 0 else self.n
                continue
            if c == "`" and end == "`":
                self.i += 1
                return
            if c == ")":
                if subshells:
                    subshells.pop()
                    self.i += 1
                    cmd_pos = True
                    current = None
                    continue
                if case_state and case_state[-1] == "pattern":
                    self.i += 1
                    case_state[-1] = "body"
                    cmd_pos = True
                    continue
                if end == ")":
                    self.i += 1
                    return
                self.i += 1
                cmd_pos = True
                continue

            if case_state and case_state[-1] == "pattern":
                # `--domain)` is a pattern, not a command.
                if c == "'":
                    self._skip_single_quoted()
                    continue
                if c == '"':
                    self._skip_double_quoted()
                    continue
                if c in "(|":
                    self.i += 1
                    continue
                word, unquoted, _ = self._read_word()
                if not word:
                    self.i += 1
                elif word == "esac" and unquoted:
                    case_state.pop()
                    cmd_pos = True
                continue

            if self.t.startswith("((", self.i) and cmd_pos and not cond_depth:
                self._skip_arithmetic()
                cmd_pos = False
                continue
            if c == "(":
                if cmd_pos:
                    self.i += 1
                    subshells.append(")")
                else:
                    self._skip_array_literal()
                continue

            if self.t.startswith(";;&", self.i):
                self.i += 3
                if case_state:
                    case_state[-1] = "pattern"
                current = None
                continue
            if self.t.startswith(";;", self.i) or self.t.startswith(";&", self.i):
                self.i += 2
                if case_state:
                    case_state[-1] = "pattern"
                cmd_pos = True
                current = None
                continue
            if c == ";":
                self.i += 1
                cmd_pos = True
                in_word_list = False
                current = None
                continue
            if (self.t.startswith("&&", self.i) or self.t.startswith("||", self.i)
                    or self.t.startswith("|&", self.i)):
                self.i += 2
                cmd_pos = True
                current = None
                continue
            if c in "|&":
                self.i += 1
                cmd_pos = True
                current = None
                continue
            if c in "<>":
                self._read_redirection()
                continue
            # A word that begins with a quote is still read as a WORD rather
            # than skipped as a span: `trap 'cleanup' EXIT` has to arrive as
            # an argument of `trap`, or the handler is never looked at.
            word, unquoted, offset = self._read_word()
            if not word:
                self.i += 1
                continue

            if word.isdigit() and self.i < self.n and self.t[self.i] in "<>":
                self._read_redirection()              # the fd of `2>&1`
                continue

            if cond_depth:
                if word == "]]":
                    cond_depth -= 1
                    cmd_pos = False
                continue

            if naming_function:
                naming_function = False
                self.out.defs.setdefault(word, offset)
                self._skip_blanks()
                if self.t.startswith("()", self.i):
                    self.i += 2
                cmd_pos = True
                continue

            if cmd_pos and _ASSIGNMENT.match(word):
                # Checked before the `name()` shape below: `CLOSING_NOTES=()`
                # is an empty array, and reading it as a definition named
                # `CLOSING_NOTES=` put five such phantoms in `defs`.
                if word.endswith("=") and self.i < self.n and self.t[self.i] == "(":
                    self._skip_array_literal()
                continue                              # cmd_pos stays True

            if (cmd_pos and unquoted and _FUNCTION_NAME.match(word)
                    and self.t.startswith("()", self.i)):
                self.out.defs.setdefault(word, offset)
                self.i += 2
                cmd_pos = True
                continue

            if not cmd_pos:
                if current is not None:
                    current.raw_args.append(word)
                    if unquoted:
                        current.args.append(word)
                continue

            if in_word_list:
                if word == "do":
                    in_word_list = False
                continue
            if word == "[[":
                cond_depth += 1
                continue
            if word == "function":
                naming_function = True
                continue
            if word in ("for", "select"):
                in_word_list = True
                continue
            if word == "case":
                case_state.append("pattern")
                self._skip_blanks()
                self._read_word()                     # the subject
                while self.i < self.n and self.t[self.i] in " \t\n":
                    self.i += 1
                self._read_word()                     # `in`
                cmd_pos = False
                continue
            if word == "esac":
                if case_state:
                    case_state.pop()
                continue
            if word in ("source", "."):
                self._skip_blanks()
                raw, _, target_offset = self._read_word()
                self.out.sources.append((raw, target_offset))
                cmd_pos = False
                continue
            if word in BASH_KEYWORDS:
                continue
            if not unquoted:
                cmd_pos = False
                continue

            current = Command(word, offset)
            self.out.commands.append(current)
            cmd_pos = False


def _scan(text: str) -> ScriptScan:
    scanner = _Scanner(text)
    scanner._parse()
    out = scanner.out
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    out.code_lines = {bisect.bisect_right(starts, o) for o in scanner._code_offsets}
    # `trap cleanup EXIT` runs `cleanup` in THIS shell, so the argument is
    # code, not data — the only quoted text this check looks inside.
    for command in list(out.commands):
        if command.name != "trap" or not command.raw_args:
            continue
        handler = command.raw_args[0]
        if len(handler) >= 2 and handler[0] == handler[-1] and handler[0] in "'\"":
            handler = handler[1:-1]
        for nested in _scan(handler).commands:
            out.commands.append(Command(nested.name, command.offset))
    return out


def _line_of(text: str, offset: int) -> int:
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    return bisect.bisect_right(starts, offset)


# ===========================================================================
# A second, deliberately different reading of the same file
#
# The scanner above is a character lexer with nested state. When it loses the
# thread it does not stop or crash — it runs to the last byte of the file
# believing almost none of it is code, finds nothing, and every test that
# asks "is anything wrong here" answers no. That happened: an apostrophe in a
# comment inside `ASSETS=( … )` in scripts/vendor-assets.sh swallowed 71% of
# the file, and the gate stayed green over an undefined function injected
# anywhere past line 55.
#
# So a second model reads the same text by an unrelated method — one pass over
# LINES, no recursion — and says where bash would be reading commands. A lexer
# bug cannot appear in both, because they share no mechanism.
#
# ## Why this one answers three ways and not two
#
# Its first version answered two: code, or not code. That made every construct
# it did not model a coin toss between a hole and a false alarm, and it landed
# on both sides within one week:
#
#   * `SSH_OPTS=(-o BatchMode=no …` — a word list with its first element on
#     the opening line. Not matched by the "array opens here" regex, so its
#     continuation lines were called CODE, the scanner rightly did not read
#     them as commands, and four more options in a list that already ships
#     turned the gate red on correct shell. Nine such arrays ship today; the
#     one at deploy/install.sh:2002 sat three lines under the limit.
#   * `log "peer setup uses cat <<EOF on the far side"` — a heredoc opener
#     mentioned inside a string. The line model believed a heredoc had opened
#     and skipped 497 lines of deploy/install.sh, silently, share 0.815, all
#     green.
#
# A model that must commit to one of two answers about a construct it cannot
# parse will keep producing one of those two failures. So this one is
# MONOTONE: a line is `certain` only when the model can positively prove it is
# at command level, and everything else — including everything after any
# construct the model does not understand — is `unknown`. `unknown` is
# compared against nothing.
#
# The cost is sensitivity, and it is bounded and visible: a modelling gap
# shrinks `certain`, and `test_the_flat_model_still_reads_most_of_each_script`
# fails when `certain` drops below a share of the file. The alternative cost —
# a red gate on shell that is correct — is the one that gets a test deleted.
# ===========================================================================

_FLAT_COMMENT = re.compile(r"^[ \t]*#")

#: Characters that end a heredoc delimiter word.
_DELIMITER_END = set(" \t;&|<>()")


@dataclass
class _FlatLine:
    """What one line does to the line model's state."""

    quote: str | None = None    # quote still open at end of line
    depth: int = 0              # net unclosed `(` on this line
    continued: bool = False     # ends with an unquoted backslash
    #: heredocs this line opens, as (delimiter, strip-leading-tabs)
    heredocs: list[tuple[str, bool]] = field(default_factory=list)
    understood: bool = True     # False when the model gave up on this line


def _flat_scan_line(line: str, quote: str | None) -> _FlatLine:
    """Walk one line, from a known quoting state, and report what it did.

    Heredoc openers are picked up HERE, mid-walk, rather than by a regex over
    the finished line. Both ways of doing it by regex are wrong: over the raw
    line, `log "peer setup uses cat <<EOF"` opens a heredoc that never closes
    and silences 497 lines of deploy/install.sh; over the line with quoted
    spans removed, `cat <<'EOF'` loses its delimiter with the quotes and the
    body gets called code. In the middle of the walk both are simply right —
    the `<<` is only an opener when it is reached outside quotes and outside
    the comment, and the delimiter is read with its own quoting from the raw
    text.
    """
    out = _FlatLine(quote=quote)
    i = 0
    while i < len(line):
        c = line[i]
        if quote == "'":
            if c == "'":
                quote = None
        elif quote == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quote = None
        elif c == "\\":
            if i == len(line) - 1:
                out.continued = True
            i += 2
            continue
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break                            # rest of the line is a comment
        elif line.startswith("<<<", i):
            i += 3                           # here-STRING: no body follows
            continue
        elif line.startswith("<<", i):
            j = i + 2
            strip = j < len(line) and line[j] == "-"
            if strip:
                j += 1
            while j < len(line) and line[j] in " \t":
                j += 1
            delimiter, j = _read_delimiter(line, j)
            if not delimiter:
                out.understood = False       # cannot see where the body ends
                break
            out.heredocs.append((delimiter, strip))
            i = j
            continue
        elif c in "'\"":
            quote = c
        elif c == "(":
            out.depth += 1
        elif c == ")":
            out.depth -= 1
        i += 1
    out.quote = quote
    return out


def _read_delimiter(line: str, i: int) -> tuple[str, int]:
    """The heredoc delimiter starting at `i`, unquoted, and where it ends.

    Quoting is per character, not per word: bash reads `<<"EO"F` and `<<\\EOF`
    and `<<'EOF'` as the same delimiter, `EOF`, and turns expansion off for
    all three.
    """
    out: list[str] = []
    while i < len(line) and line[i] not in _DELIMITER_END:
        c = line[i]
        if c == "\\":
            if i + 1 < len(line):
                out.append(line[i + 1])
            i += 2
            continue
        if c in "'\"":
            end = line.find(c, i + 1)
            if end < 0:
                return "", i                 # unterminated: not parsable
            out.append(line[i + 1:end])
            i = end + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), i


def _flat_line_model(text: str) -> tuple[set[int], set[int]]:
    """(certain command-level lines, lines the model will not vouch for).

    Monotone: nothing reaches `certain` that the model cannot prove. A line
    is certain only when the model arrived at it in the plain top-level state
    — no heredoc body open, no quote carried over from an earlier line, no
    unclosed `(` from an earlier line, and no earlier line it failed to parse.
    """
    certain: set[int] = set()
    unknown: set[int] = set()
    pending: list[tuple[str, bool]] = []
    heredoc: tuple[str, bool] | None = None
    quote: str | None = None
    depth = 0
    lost = False

    for n, line in enumerate(text.split("\n"), 1):
        if heredoc is not None:
            delimiter, strip = heredoc
            probe = line.lstrip("\t") if strip else line
            unknown.add(n)
            if probe.rstrip("\r") == delimiter:
                heredoc = pending.pop(0) if pending else None
            continue
        if not line.strip():
            continue                         # blank: neither, and not counted
        if lost:
            unknown.add(n)
            continue
        if quote is not None or depth > 0:
            # Inside something that began earlier: a multi-line literal, a
            # word list, a subshell. The model does not claim to know which,
            # and monotone means it does not guess.
            unknown.add(n)
            scanned = _flat_scan_line(line, quote)
            quote, lost = scanned.quote, not scanned.understood
            depth = max(0, depth + scanned.depth)
            continue
        if _FLAT_COMMENT.match(line):
            # bash reads the `#` at command level and drops the rest, so the
            # scanner must have been here. This is the line the vendor-assets
            # desync started on.
            certain.add(n)
            continue

        certain.add(n)
        scanned = _flat_scan_line(line, None)
        quote, lost = scanned.quote, not scanned.understood
        depth = max(0, depth + scanned.depth)
        if scanned.heredocs:
            heredoc, pending = scanned.heredocs[0], list(scanned.heredocs[1:])
    return certain, unknown


def _unread_runs(text: str, scan: ScriptScan) -> list[list[int]]:
    """Contiguous stretches of PROVEN code lines the scanner never read."""
    certain, _unknown = _flat_line_model(text)
    runs: list[list[int]] = []
    current: list[int] = []
    for line in sorted(certain):
        if line in scan.code_lines:
            if current:
                runs.append(current)
                current = []
            continue
        if current and line != current[-1] + 1:
            runs.append(current)
            current = []
        current.append(line)
    if current:
        runs.append(current)
    return runs


# ===========================================================================
# Resolution
# ===========================================================================

@dataclass(frozen=True)
class MissingCall:
    script: str
    line: int
    name: str

    def __str__(self) -> str:
        return f"{self.script}:{self.line}: {self.name}"


@dataclass(frozen=True)
class OpaqueSource:
    script: str
    line: int
    raw: str

    def __str__(self) -> str:
        return f"{self.script}:{self.line}: source {self.raw}"


_SINGLE_ASSIGNMENT = r"^[ \t]*{name}=(.+)$"


def _resolve_source_target(script: str, raw: str, text: str,
                           known: set[str]) -> str | None:
    """Turn the raw word after `source` into a repository path, or None.

    None means "this check cannot see what that pulls in" — never "it pulls in
    nothing".
    """
    target = raw.strip()
    if len(target) >= 2 and target[0] == target[-1] and target[0] in "'\"":
        target = target[1:-1]
    script_dir = posixpath.dirname(script)

    # One indirection through a variable, and only when the file assigns that
    # variable exactly once: `. "$_lib"` in deploy/preflight.sh, where `_lib`
    # is the distro library. Two assignments mean the value depends on which
    # branch ran, which is not something to guess at.
    var = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", target)
    if var:
        assignments = re.findall(_SINGLE_ASSIGNMENT.format(name=re.escape(var.group(1))),
                                 text, re.M)
        if len(assignments) != 1:
            return None
        target = assignments[0].strip()
        if len(target) >= 2 and target[0] == target[-1] and target[0] in "'\"":
            target = target[1:-1]

    target = target.replace(_SCRIPT_DIR_INLINE, script_dir or ".")
    for name, (value, _idiom) in PATH_VARIABLES.items():
        value = value % {"dir": script_dir or "."}
        target = target.replace("${" + name + "}", value).replace("$" + name, value)
    if "$" in target or target.startswith("/"):
        return None
    resolved = posixpath.normpath(target)
    return resolved if resolved in known else None


def _guarded_names(scan: ScriptScan) -> set[str]:
    """Names the script itself tests for with `declare -F`.

    `deploy/lib/common.sh` does this for `pkg_list`, which lives in
    `deploy/lib/distro.sh` and is only present when the installer sourced
    both. The guard is the script saying, in bash, "this may be absent and I
    handle that" — but it still has to exist SOMEWHERE committed, or the guard
    is just a silent no-op forever.

    `declare -F` only, never `declare -f`: the lower-case form PRINTS a
    function's body, and `scripts/wizard.sh` uses `$(declare -f run_install)`
    to ship that body over ssh. That is not a script saying "this may be
    absent"; the name has to exist for the serialisation to carry anything,
    so it must keep resolving the ordinary way.
    """
    names: set[str] = set()
    for command in scan.commands:
        if command.name in ("declare", "typeset") and "-F" in command.args:
            names |= {a for a in command.args if not a.startswith("-")}
    return names


def analyse(texts: dict[str, str]) -> tuple[list[MissingCall], list[OpaqueSource]]:
    """Resolve every call in every script of `texts` against `texts`."""
    scans = {path: _scan(text) for path, text in texts.items()}
    everything_defined = {name for scan in scans.values() for name in scan.defs}

    def closure(path: str, seen: set[str] | None = None) -> tuple[set[str], list[OpaqueSource]]:
        seen = set() if seen is None else seen
        opaque: list[OpaqueSource] = []
        if path in seen:
            return seen, opaque
        seen.add(path)
        for raw, offset in scans[path].sources:
            target = _resolve_source_target(path, raw, texts[path], set(texts))
            if target is None:
                opaque.append(OpaqueSource(path, _line_of(texts[path], offset), raw))
                continue
            _, deeper = closure(target, seen)
            opaque += deeper
        return seen, opaque

    missing: list[MissingCall] = []
    opaque_all: list[OpaqueSource] = []
    for path in sorted(texts):
        reachable, opaque = closure(path)
        opaque_all += opaque
        available = {name for p in reachable for name in scans[p].defs}
        guarded = _guarded_names(scans[path])
        for command in scans[path].commands:
            name = command.name
            if (name in available or name in BASH_BUILTINS or name in BASH_KEYWORDS
                    or name in EXTERNAL_COMMANDS):
                continue
            if name in guarded and name in everything_defined:
                continue
            missing.append(MissingCall(path, _line_of(texts[path], command.offset), name))
    # A library reached from three callers yields the same unfollowable
    # `source` three times; report the fact once.
    return missing, sorted(set(opaque_all), key=lambda o: (o.script, o.line))


# ===========================================================================
# Reading what git has, and only what git has
# ===========================================================================

_GIT = shutil.which("git")

def _git_unavailable() -> str | None:
    """Why this check cannot run here, or None when it can.

    The reason says, in words, that nothing was checked. A skip whose reason
    reads like a clean bill of health is the pattern CLAUDE.md names: "could
    not look" and "looked, found nothing" have to be distinguishable in the
    summary, because only one of them means the shell is resolvable.
    """
    if _GIT is None:
        return ("CHECK DID NOT RUN: no git on PATH, so the COMMITTED shell "
                "scripts could not be read. Nothing about them was verified "
                "— this is not a pass.")
    probe = subprocess.run([_GIT, "-C", str(REPO), "rev-parse", "--verify", "HEAD"],
                           capture_output=True)
    if probe.returncode != 0:
        return ("CHECK DID NOT RUN: no HEAD commit in " + str(REPO) + " (a "
                "packaged tarball or a repository with no history). The "
                "committed shell scripts were NOT analysed — this is not a pass.")
    return None


_NO_GIT = _git_unavailable()
needs_git = pytest.mark.skipif(_NO_GIT is not None, reason=_NO_GIT or "")


def _git_out(*args: str) -> bytes:
    assert _GIT is not None
    return subprocess.run([_GIT, "-C", str(REPO), *args],
                          capture_output=True, check=True).stdout


@cache
def _shell_scripts_at(rev: str) -> tuple[str, ...]:
    """Paths of the `.sh` files in a commit — the tree, not the index.

    `git ls-files` would answer from the index, where a `git add`ed but
    uncommitted library is already visible; that is the exact state this test
    has to see through.
    """
    # No `-- "*.sh"` pathspec: `git ls-tree` matches a path by prefix, not by
    # glob, and answers that one with an empty list -- which would have made
    # every test in this file pass over nothing at all.
    out = _git_out("ls-tree", "-r", "-z", "--name-only", rev)
    return tuple(sorted(p for p in out.decode("utf-8").split("\0")
                        if p.endswith(".sh")))


@cache
def _texts_at(rev: str) -> dict[str, str]:
    # Cached: eight tests over fifteen files is 120 `git show` processes, and
    # on Windows that is seconds of wall clock for bytes that cannot change
    # while the suite runs. A commit is immutable, so the cache cannot go
    # stale within one run.
    return {p: _git_out("show", f"{rev}:{p}").decode("utf-8")
            for p in _shell_scripts_at(rev)}


# ===========================================================================
# Tests
# ===========================================================================

#: EVERY committed shell script, named. A pathspec typo, a renamed directory
#: or a `git ls-tree` that returns nothing would otherwise leave this whole
#: file green over an empty list — the shape of "a parametrised list came out
#: empty and was skipped in silence" that CLAUDE.md names. Naming nine of the
#: fifteen left six that could be dropped from discovery with the main gate
#: still green, so the list is complete: a new script joins the corpus
#: automatically, and one leaving it has to be struck from here by hand.
CORE_SCRIPTS = {
    "deploy/install.sh",
    "deploy/lib/common.sh",
    "deploy/lib/distro.sh",
    "deploy/postgres/fix-pg-hba.sh",
    "deploy/preflight.sh",
    "deploy/rollback.sh",
    "scripts/deploy.sh",
    "scripts/inventory-push.sh",
    "scripts/lib/build-package.sh",
    "scripts/lib/check-line-endings.sh",
    "scripts/secrets-init.sh",
    "scripts/smoke-test.sh",
    "scripts/tail-logs.sh",
    "scripts/vendor-assets.sh",
    "scripts/wizard.sh",
}


@needs_git
def test_every_call_in_a_committed_shell_script_has_a_committed_definition():
    """The deploy dies at the call, on the host, mid-install.

    21 September 2026: `deploy/install.sh` was committed calling
    `migrate_legacy_state_markers`; its definition stayed in an uncommitted
    `deploy/lib/common.sh`. `bash -n` was happy, 5276 tests passed, and the
    installer died on the Ubuntu host at line 5586 with `command not found`,
    right after the operator said yes. Whether that leaves the host untouched
    or half-configured depends only on which step the missing call sits in.
    """
    paths = set(_shell_scripts_at("HEAD"))
    assert CORE_SCRIPTS == paths, (
        "the corpus is not the list this file says it covers. Equality, not "
        "a subset: a subset check passes over a sixteenth script nobody "
        "added to CORE_SCRIPTS, which is a shipped script no test resolves.\n"
        f"  discovery found and CORE_SCRIPTS omits: {sorted(paths - CORE_SCRIPTS)}\n"
        f"  CORE_SCRIPTS names and discovery lost: {sorted(CORE_SCRIPTS - paths)}")

    missing, _ = analyse(_texts_at("HEAD"))
    assert not missing, (
        "these words would be executed as commands by a committed script, and "
        "nothing committed defines them. Line numbers are lines of the "
        "COMMITTED file (`git show HEAD:<path>`), which may differ from your "
        "working tree — that difference is the bug this test looks for.\n"
        "If the name is a shell function, commit the file that defines it. If "
        "it is a binary the host provides, add it to EXTERNAL_COMMANDS in this "
        "file, where the claim gets reviewed.\n"
        + "\n".join(f"  {m}" for m in missing))


@needs_git
def test_every_source_directive_is_followed_or_declared():
    """A library this check cannot see through would make its silence worthless.

    If `install.sh` starts sourcing something resolved at runtime, every
    function that file provides becomes invisible here — and the test above
    would either flood with false alarms or, worse, be "fixed" by dumping the
    names into EXTERNAL_COMMANDS. An unfollowable `source` is reported as its
    own failure so the decision is made deliberately, in OPAQUE_SOURCES, with
    a reason.
    """
    _, opaque = analyse(_texts_at("HEAD"))
    undeclared = [o for o in opaque if (o.script, o.raw) not in OPAQUE_SOURCES]
    assert not undeclared, (
        "this check cannot follow these `source` directives, so it cannot know "
        "which functions they define. 'Cannot see' is not 'nothing there': read "
        "each target and, if it really is data rather than shell, declare it in "
        "OPAQUE_SOURCES with the reason.\n"
        + "\n".join(f"  {o}" for o in undeclared))


@needs_git
def test_declared_exceptions_are_still_real():
    """A stale allowance is a hole nobody can see.

    Every entry in OPAQUE_SOURCES names a `source` that exists today. When one
    of them is deleted or rewritten the entry has to go too, or the next
    unfollowable source at the same path inherits a blessing granted for
    something else entirely.
    """
    _, opaque = analyse(_texts_at("HEAD"))
    live = {(o.script, o.raw) for o in opaque}
    stale = sorted(set(OPAQUE_SOURCES) - live)
    assert not stale, (
        "OPAQUE_SOURCES allows `source` directives that no longer exist; remove "
        f"them: {stale}")


@needs_git
def test_source_path_variables_still_mean_what_resolution_assumes():
    """Resolution that trusts a variable it never read is back to guessing.

    `${SCRIPT_DIR}/lib/common.sh` is followed to `deploy/lib/common.sh` only
    because SCRIPT_DIR is the script's own directory. If some script later
    sets SCRIPT_DIR to a staging path, every symbol common.sh provides would
    be resolved from the wrong file and this check would quietly agree with
    whatever it found. Iterating PATH_VARIABLES — the same table the resolver
    expands from — is what stops a variable being expanded with nothing
    checking it, which is how `${SRC_ROOT}` (`"${2:-}"`, caller-supplied) was
    being rewritten to the repository root on trust.
    """
    texts = _texts_at("HEAD")
    checked: set[str] = set()
    wrong: list[str] = []
    for path, text in texts.items():
        for raw, _ in _scan(text).sources:
            for var, (_value, idiom) in PATH_VARIABLES.items():
                if f"${{{var}}}" not in raw and f"${var}" not in raw:
                    continue
                checked.add(var)
                if not re.search("^" + idiom + "$", text, re.M):
                    wrong.append(f"{path}: sources via ${var}, which this file "
                                 f"does not set with the expected idiom")
    assert checked == set(PATH_VARIABLES), (
        "every variable the resolver expands has to be exercised by a real "
        "`source` here, or it is an expansion nothing verifies: "
        f"unexercised {sorted(set(PATH_VARIABLES) - checked)}")
    assert not wrong, "\n".join(wrong)


@needs_git
def test_no_shell_script_escapes_discovery_by_having_no_sh_suffix():
    """A shipped script nobody analyses is a gap that reads like coverage.

    The corpus is `*.sh` because that is what the tree happens to contain
    today. `deploy/tools/` or a hook committed without an extension would ship
    in the same tarball (the packager takes everything git tracks outside
    tests/, docs/, watcher/, aggregator/, secrets/, scratchpad/) and would be
    silently outside this test.
    """
    # `git grep` exits 1 on "no match", which is an answer, not an error — so
    # this one call does not go through _git_out's check=True.
    grep = subprocess.run(
        [_GIT, "-C", str(REPO), "grep", "-I", "-l", "-E",
         r"^#!.*(bash|\bsh)\b", "HEAD", "--"], capture_output=True)
    assert grep.returncode in (0, 1), grep.stderr.decode("utf-8", "replace")
    candidates = [line.split(":", 1)[1]
                  for line in grep.stdout.decode("utf-8").splitlines() if ":" in line]
    assert candidates, ("no committed file has a shell shebang at all — this "
                        "check is looking at the wrong tree")
    analysed = set(_shell_scripts_at("HEAD"))
    stragglers = []
    for path in candidates:
        if path in analysed:
            continue
        first = _git_out("show", f"HEAD:{path}").decode("utf-8", "replace").split("\n", 1)[0]
        if re.match(r"^#!.*(bash|\bsh)\b", first):
            stragglers.append(path)
    assert not stragglers, (
        "these committed files are shell scripts but do not end in .sh, so "
        "nothing resolves their function calls. Rename them or widen "
        f"_shell_scripts_at: {sorted(stragglers)}")


def test_no_function_names_hidden_as_binaries():
    """The one repair that would turn this test back into a rubber stamp.

    Faced with `migrate_legacy_state_markers: not defined`, the five-second
    fix is to paste the name into EXTERNAL_COMMANDS. Every function in this
    repository's shell is snake_case and no host binary here is, bar the two
    named in UNDERSCORED_BINARIES, so that repair is detectable and it is
    refused.
    """
    smuggled = sorted(n for n in EXTERNAL_COMMANDS
                      if "_" in n and n not in UNDERSCORED_BINARIES)
    assert not smuggled, (
        "these look like shell functions, not binaries. A missing function is "
        "fixed by committing its definition, not by declaring it an external "
        f"command: {smuggled}")


@needs_git
def test_external_command_inventory_has_no_dead_entries():
    """An inventory that outlives its callers stops being reviewed.

    Each name here is a claim that the host provides that binary. When the
    last call site goes away the claim is no longer checked by anything, and
    the list drifts into a general-purpose silencer.
    """
    texts = _texts_at("HEAD")
    used = {c.name for text in texts.values() for c in _scan(text).commands}
    assert used, "the scanner found no commands at all in the whole corpus"
    unused = sorted(EXTERNAL_COMMANDS - used)
    assert not unused, (
        "EXTERNAL_COMMANDS names binaries nothing calls any more; drop them: "
        f"{unused}")


#: The longest stretch of code lines the scanner may miss in one place.
#: Measured across the whole corpus on 21 Sep 2026: the longest is ONE line
#: (deploy/install.sh:2003, a multi-line array literal the flat model does not
#: recognise, and scripts/smoke-test.sh:672, a process substitution inside a
#: quoted remote command). Three leaves room for that kind of imprecision and
#: none at all for a desync: the vendor-assets one was 70 lines.
_MAX_UNREAD_RUN = 3

#: And a ceiling on the scattered ones, so the two models cannot drift apart a
#: line at a time without anybody looking. Two today.
_MAX_UNREAD_TOTAL = 10

#: Re-measured after the line model was made monotone: ONE disagreement left
#: in the whole corpus (scripts/smoke-test.sh:672, a `<( … )` inside a quoted
#: remote command), longest run 1. Everything the model used to get wrong in
#: the other direction — multi-line word lists, `<<'EOF'`, `<<\EOF` — is now
#: `unknown` and compared against nothing.


@needs_git
def test_the_scanner_reads_each_script_as_code_end_to_end():
    """A lexer that loses the thread answers "nothing wrong" about the rest.

    scripts/vendor-assets.sh, 21 September: `# … Chart.js's ~200 KB` inside
    `ASSETS=( … )`. The apostrophe opened a quoted run that closed thirteen
    lines later, the scan saw six commands out of forty-one, and an undefined
    function injected anywhere past line 55 came back clean — the gate green,
    the corpus 71% unread.

    Every other check in this file compares things the scanner FOUND. This is
    the only one that asks where it LOOKED, which is why it is the only one
    that can see that failure: the definition cross-check below missed it
    outright, because vendor-assets defines its four functions at lines 36-39,
    above the point where the scan came apart.
    """
    texts = _texts_at("HEAD")
    assert texts, "no scripts to read — discovery is broken"
    total = 0
    blind: list[str] = []
    for path, text in sorted(texts.items()):
        scan = _scan(text)
        certain, _unknown = _flat_line_model(text)
        assert certain, f"{path}: the line model proves nothing about this file"
        for run in _unread_runs(text, scan):
            total += len(run)
            if len(run) > _MAX_UNREAD_RUN:
                blind.append(f"{path}: lines {run[0]}-{run[-1]} ({len(run)} of "
                             f"{len(certain)} proven code lines) never read as "
                             "code")
    assert not blind, (
        "the two readings of these lines disagree, and only one of them can be "
        "right. The line model lists a line here only when it can prove the "
        "line is at command level, so the likely reading is that the scanner "
        "went into a string, a comment or a word list somewhere above the "
        "first line listed and never came out — in which case nothing in the "
        "stretch was resolved and no other test here would notice. Check the "
        "scanner first; if it turns out to be right, the fix belongs in "
        "`_flat_scan_line`, and it is to move the construct into `unknown`, "
        "never to teach the model a new shape of `certain`:\n"
        + "\n".join(f"  {b}" for b in blind))
    assert total <= _MAX_UNREAD_TOTAL, (
        f"{total} proven code lines are read differently by the two models "
        f"(limit {_MAX_UNREAD_TOTAL}). Scattered, so probably not a desync — "
        "but the two readings are drifting apart and one of them is wrong.")


#: The share of each script's non-blank lines the flat oracle must still call
#: code. Measured 21 Sep 2026: 0.556 on the 31-line deploy/postgres/
#: fix-pg-hba.sh (an 11-line awk program in single quotes), 0.70-0.99
#: everywhere else. This is a floor against the oracle COLLAPSING, not a
#: measure of its quality.
_MIN_FLAT_CODE_SHARE = 0.45


def test_the_scanner_does_not_claim_to_have_read_what_is_not_code():
    """The reach check has two inputs, and only one of them was guarded.

    `code_lines` is filled by a single `append` in the scanner's command
    loop. Over-report it — make it every line in the file — and the reach
    check can never fire again: the set it subtracts from covers everything,
    no run is ever left, and all 62 tests here pass. Measured, exactly that.

    The line model's side has a floor under it. This is the other side: a
    quoted heredoc body is data by definition, so a scanner that says it read
    that as a command is not measuring where it looked.
    """
    text = ("helper() { :; }\n"          # 1
            "cat <<'EOF'\n"              # 2
            "this is data\n"             # 3
            "so is this\n"               # 4
            "EOF\n"                      # 5
            "helper\n")                  # 6
    scan = _scan(text)
    assert {3, 4} & scan.code_lines == set(), (
        "the scanner reports having read a quoted heredoc body at command "
        f"level; `code_lines` is not measuring anything: {sorted(scan.code_lines)}")
    assert {1, 2, 6} <= scan.code_lines, (
        "the scanner did not read the plain command lines around a heredoc: "
        f"{sorted(scan.code_lines)}")

    # And the comparison itself: a scanner that read nothing must come back
    # with every proven line, not with an empty answer. Two runs, not one —
    # the heredoc body between them is `unknown`, and a run is a stretch of
    # ADJACENT proven lines, so an unknown stretch splits it. That is why
    # `_MAX_UNREAD_TOTAL` exists next to `_MAX_UNREAD_RUN`: a blind region
    # chopped into short runs still has to be visible.
    certain, _unknown = _flat_line_model(text)
    assert sorted(certain) == [1, 2, 6]
    assert _unread_runs(text, ScriptScan()) == [[1, 2], [6]]


#: Shell that is correct, that the two readings must not fight over, and that
#: the round-2 line model DID fight over. Each entry ends with `last_call` on
#: its own line: no run may be reported anywhere, AND that final line must
#: still be PROVEN code — a model that answers "unknown" from the construct
#: onwards produces no runs either, and that is the silent half of the same
#: failure.
_AGREEMENT_FIXTURES = {
    "word list with its first element on the opening line": (
        "SSH_OPTS=(-o BatchMode=yes\n"
        "    -o ConnectTimeout=10\n"
        "    -o StrictHostKeyChecking=accept-new\n"
        "    -o ServerAliveInterval=15\n"
        "    -o ServerAliveCountMax=4\n"
        "    -o LogLevel=ERROR\n"
        ")\n"
        "last_call\n"),
    "word list opening on its own line, with a comment in it": (
        "ASSETS=(\n"
        "  # uPlot — ~45 KB against Chart.js's ~200 KB, and far faster\n"
        '  "uPlot.iife.min.js|1.6.31"\n'
        "  # note 1) first, 2) second\n"
        '  "htmx.min.js|2.0.4"\n'
        ")\n"
        "last_call\n"),
    "heredoc with a backslash-quoted delimiter": (
        "cat <<\\EOF\n line 1\n line 2\n line 3\n line 4\n line 5\nEOF\n"
        "last_call\n"),
    "heredoc with a single-quoted delimiter": (
        "cat <<'EOF'\n line 1\n line 2\n line 3\n line 4\n line 5\nEOF\n"
        "last_call\n"),
    "heredoc with a double-quoted delimiter": (
        'cat <<"EOF"\n line 1\n line 2\n line 3\n line 4\n line 5\nEOF\n'
        "last_call\n"),
    "tab-stripped heredoc": (
        "cat <<-EOF\n\t line 1\n\t line 2\n\t line 3\n\tEOF\n"
        "last_call\n"),
    "a string that merely mentions a heredoc": (
        'log "peer setup uses cat <<EOF on the far side"\n'
        "helper\nhelper\nhelper\nhelper\n"
        "last_call\n"),
    "a comment that mentions a heredoc": (
        "helper   # see cat <<EOF over there\n"
        "helper\nhelper\nhelper\n"
        "last_call\n"),
    "here-string": (
        "grep -q x <<<\"$payload\"\n"
        "helper\n"
        "last_call\n"),
    "multi-line subshell": (
        "(\n  helper\n  helper\n)\n"
        "last_call\n"),
    "case arms": (
        'case "$1" in\n'
        "  --domain)   helper ;;\n"
        "  --web-port) helper ;;\n"
        "  *)          helper ;;\n"
        "esac\n"
        "last_call\n"),
    "multi-line single-quoted program": (
        "awk '\n  BEGIN { print 1 }\n  { print }\n' /dev/null\n"
        "last_call\n"),
}


@pytest.mark.parametrize("name", sorted(_AGREEMENT_FIXTURES))
def test_the_two_readings_do_not_fight_over_correct_shell(name):
    """A gate that turns red on shell that is right gets switched off.

    Both of these shipped in the round-2 line model and both are routine:

      * `SSH_OPTS=(-o BatchMode=no …` — a word list with its first element on
        the opening line. Nine ship today; adding four options to the one at
        scripts/deploy.sh:271 turned the gate red, and `bash -n` was happy.
      * `<<\\EOF` — a delimiter quoted with a backslash. A three-line body was
        enough.

    The line model is monotone now: anything it cannot prove is at command
    level is `unknown`, and `unknown` is compared against nothing. That is
    what makes a modelling gap cost sensitivity instead of turning correct
    shell red — so this test checks BOTH halves, no run reported and the
    final line still proven.
    """
    text = "helper() { :; }\nlast_call() { :; }\n" + _AGREEMENT_FIXTURES[name]
    runs = _unread_runs(text, _scan(text))
    assert runs == [], f"the two readings disagree over correct shell: {runs}"

    certain, unknown = _flat_line_model(text)
    last = text.rstrip("\n").count("\n") + 1
    assert last in certain, (
        "no disagreement was reported because the line model stopped "
        f"claiming anything: line {last} (`last_call`) is "
        f"{'unknown' if last in unknown else 'unclassified'}, and from the "
        "construct onwards the reach check is looking at nothing")


def test_the_line_model_gives_up_out_loud_when_it_cannot_parse_a_heredoc():
    """The one branch where "I do not know" has to be written down.

    `cat <<'EOF` — the quote around the delimiter never closes — is shell
    bash itself rejects, so it should never appear. If it does, the model
    cannot tell where the body ends, and the monotone rule says it must stop
    claiming rather than guess a delimiter and resynchronise on the wrong
    line. Without a test this branch is unreachable-looking code that a
    later edit deletes as dead, and the next unparsable construct silently
    becomes `certain`.
    """
    scanned = _flat_scan_line("cat <<'EOF", None)
    assert scanned.understood is False
    assert scanned.heredocs == []

    certain, unknown = _flat_line_model("helper\ncat <<'EOF\nanything\nhelper\n")
    assert certain == {1, 2}, certain
    assert unknown == {3, 4}, unknown


def test_the_flat_model_is_not_fooled_by_an_apostrophe_in_a_comment():
    """An oracle that repeats the lexer's mistake agrees with it, silently.

    `_flat_scan_line` stops at an unquoted `#` for one reason: otherwise the
    apostrophe in `# don't do this` opens a literal that runs to the next
    quote, every line after it drops to `unknown`, and the reach check above
    compares against nothing. That rule changes no outcome on today's corpus
    — every comment with an apostrophe in it happens to be a full-line one —
    which is exactly why it needs a test of its own rather than being trusted
    to stay correct because nothing complains.
    """
    assert _flat_line_model("helper   # don't do this\nmissing_one\n")[0] == {1, 2}
    assert _flat_line_model("# Chart.js's ~200 KB\nmissing_one\n")[0] == {1, 2}


@needs_git
def test_the_flat_model_still_reads_most_of_each_script():
    """A blind oracle cannot contradict anything, and nothing says so.

    The reach check only reports lines the oracle calls code and the scanner
    does not. If the oracle loses the thread instead, its side of the
    comparison shrinks and every file goes quiet — the same failure, one
    layer up.
    """
    thin = []
    for path, text in sorted(_texts_at("HEAD").items()):
        non_blank = sum(1 for line in text.split("\n") if line.strip())
        assert non_blank, f"{path}: empty file in the corpus"
        certain, unknown = _flat_line_model(text)
        assert certain | unknown <= set(range(1, text.count("\n") + 2))
        share = len(certain) / non_blank
        if share < _MIN_FLAT_CODE_SHARE:
            thin.append(f"{path}: the line model proves only {share:.0%} of the "
                        f"non-blank lines ({len(certain)} of {non_blank}, with "
                        f"{len(unknown)} unknown)")
    assert not thin, (
        "the second reading has given up on too much of these files, so it can "
        "no longer contradict the scanner over them. Because the model is "
        "monotone, this is what a modelling gap looks like — it shows up as "
        "lost sensitivity here rather than as a red gate on correct shell:\n"
        + "\n".join(thin))


@needs_git
def test_the_scanner_still_sees_every_function_definition():
    """A lexer that desynchronises reports "all clear" about half a file.

    One unterminated quote or a heredoc delimiter read wrongly and the scanner
    swallows the rest of the script, finds no calls in it, and this whole file
    passes on a corpus it never looked at. A flat regex over the same text
    cannot desynchronise the same way, so the definitions it can see are a
    floor the scanner must reach.

    Supplementary to the reach check above, not a substitute: this one is
    blind whenever the definitions all sit above the point where the scan came
    apart, which is exactly how vendor-assets got past it.
    """
    definition = re.compile(r"^[ \t]*(?:function[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)"
                            r"[ \t]*\(\)[ \t]*\{?", re.M)
    texts = _texts_at("HEAD")
    total = 0
    gaps: list[str] = []
    for path, text in texts.items():
        by_regex = {m.group(1) for m in definition.finditer(text)}
        total += len(by_regex)
        for name in sorted(by_regex - set(_scan(text).defs)):
            gaps.append(f"{path}: {name}")
    assert total > 200, (
        f"only {total} function definitions found in the whole corpus — the "
        "regex, or the corpus, is not what this test thinks it is")
    assert not gaps, ("the scanner walked past these definitions, so it was "
                      "not reading the file as shell at that point:\n"
                      + "\n".join(gaps))


# --- the scanner, against hand-written shell -------------------------------

_SPINE = "\n".join([
    "#!/usr/bin/env bash",
    "helper() { :; }",
])


@pytest.mark.parametrize("body,expected", [
    ("missing_one", "missing_one"),
    ("helper || missing_one", "missing_one"),
    ("helper && missing_one", "missing_one"),
    ("helper; missing_one", "missing_one"),
    ("helper | missing_one", "missing_one"),
    ('x="$(missing_one)"', "missing_one"),
    ("x=`missing_one`", "missing_one"),
    ("if missing_one; then :; fi", "missing_one"),
    ("while missing_one; do break; done", "missing_one"),
    ("until missing_one; do break; done", "missing_one"),
    ("if helper; then missing_one; fi", "missing_one"),
    ("for f in a b; do missing_one; done", "missing_one"),
    ("case x in a) missing_one ;; esac", "missing_one"),
    ("( missing_one )", "missing_one"),
    ("{ missing_one; }", "missing_one"),
    ("! missing_one", "missing_one"),
    ("outer() { missing_one; }", "missing_one"),
    ("missing_one >/dev/null 2>&1", "missing_one"),
    ("VAR=1 missing_one", "missing_one"),
    ("trap missing_one EXIT", "missing_one"),
    ("trap 'missing_one' EXIT", "missing_one"),
    ("helper > >(missing_one)", "missing_one"),
    # An UNQUOTED heredoc body is a template, not data: bash expands it in
    # this shell, on this line.
    ("cat <<EOF\n$(missing_one)\nEOF", "missing_one"),
    ("cat <<-EOF\n\t$(missing_one)\n\tEOF", "missing_one"),
    ("cat <<EOF\n`missing_one`\nEOF", "missing_one"),
])
def test_scanner_reports_a_call_in_every_command_position(body, expected):
    """The bug hides in whichever position the scanner does not read.

    The installer calls functions after `||`, inside `$( )`, in `case` bodies
    and from `trap`. A scanner that only understands a word at the start of a
    line would have passed the 21 September commit just as `bash -n` did:
    `migrate_legacy_state_markers` sits on a line of its own, but
    `ensure_state_markers_dir` need not have.
    """
    missing, opaque = analyse({"s.sh": f"{_SPINE}\n{body}\n"})
    assert not opaque
    assert [m.name for m in missing] == [expected], (
        f"scanner did not report {expected} in: {body}")


@pytest.mark.parametrize("body", [
    "# missing_one",
    "echo 'missing_one'",
    'echo "missing_one"',
    "echo missing_one",
    "cat <<EOF\nmissing_one\nEOF",
    "cat <<-'EOF'\n\tmissing_one\nEOF",
    # A QUOTED delimiter, in any of its three spellings, turns expansion off
    # for the whole body — then it really is data.
    "cat <<'EOF'\n$(missing_one)\nEOF",
    'cat <<"EOF"\n$(missing_one)\nEOF',
    "cat <<\\EOF\n$(missing_one)\nEOF",
    "case missing_one in missing_one) helper ;; esac",
    "local -a units=(missing_one)",
    # A word list takes comments, and an apostrophe in one is not a quote.
    "A=(\n  # uPlot ~45 KB against Chart.js's ~200 KB\n  \"x\"\n)",
    "A=(\n  # note 1) first, 2) second\n  \"x\"\n)",
    # `)` is a control operator, so a `#` straight after it opens a comment.
    "( helper )# note don't",
    "helper missing_one",
    "x=missing_one",
    'ssh host "missing_one"',
    "[[ -n missing_one ]] || helper",
    "(( missing_one > 1 )) || helper",
    "for missing_one in a b; do helper; done",
    "helper > missing_one",
    "echo x >> missing_one",
])
def test_scanner_reports_nothing_where_the_word_is_not_a_command(body):
    """A test that cries wolf gets deleted, and then catches nothing.

    Every construct here contains the word in a position bash never looks up
    as a command. Reporting any of them would make the check unkeepable on a
    6400-line installer full of heredocs, `case` arms and remote command
    strings.

    The second half is the more important one. "Nothing was reported" is also
    what a scanner says after it has stopped reading the file — that is how
    an apostrophe in a comment inside `ASSETS=( … )` left 71% of
    scripts/vendor-assets.sh unscanned with every test green. So each
    construct is scanned again with a call to an undefined function AFTER it,
    and that call has to come back.
    """
    missing, _ = analyse({"s.sh": f"{_SPINE}\n{body}\n"})
    assert [m.name for m in missing] == [], f"false alarm in: {body}"

    after, _ = analyse({"s.sh": f"{_SPINE}\n{body}\nsentinel_after\n"})
    assert [m.name for m in after] == ["sentinel_after"], (
        f"the scanner never came back out of this construct: {body}")


def test_a_definition_in_a_sourced_file_resolves_and_one_next_door_does_not():
    """`source` is the only thing that makes another file's functions exist.

    install.sh reaches common.sh's functions because it sources it. A function
    defined in a file it does NOT source is exactly as absent, at run time, as
    one that was never written — and a check that resolved names against "all
    the shell in the repository" would have called the 21 September commit
    fine the moment somebody added the definition to any other script.
    """
    sourced = {
        "lib/a.sh": "provided() { :; }\n",
        "lib/b.sh": "elsewhere() { :; }\n",
        "main.sh": ('SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
                    'source "${SCRIPT_DIR}/lib/a.sh"\n'
                    "provided\n"
                    "elsewhere\n"),
    }
    missing, opaque = analyse(sourced)
    assert not opaque
    assert [(m.script, m.line, m.name) for m in missing] == [("main.sh", 4, "elsewhere")]


def test_a_declare_f_guard_does_not_excuse_a_function_nobody_wrote():
    """`declare -F x` says "x may be absent"; it does not say x exists.

    deploy/lib/common.sh guards its call to `pkg_list`, which lives in
    deploy/lib/distro.sh and is only there when the installer sourced both —
    a real, correct use. The same guard around a name that was never
    committed anywhere turns the call into a branch that is dead forever and
    never says so, which is how a backup silently stops containing the
    package list.
    """
    both = {
        "real.sh": ("provided() { :; }\n"),
        "caller.sh": ("declare -F provided >/dev/null && provided\n"
                      "declare -F never_written >/dev/null && never_written\n"),
    }
    missing, _ = analyse(both)
    assert [(m.line, m.name) for m in missing if m.script == "caller.sh"] == [
        (2, "never_written")]


def test_declare_lowercase_f_is_serialisation_and_not_a_guard():
    """`declare -f x` prints x's body; it does not ask whether x exists.

    scripts/wizard.sh builds its remote install with `$(declare -f
    run_install)` and pipes the text over ssh. Reading that as "the author
    handled this being absent" would excuse a call to a function defined in
    a file this one never sources — which is the 21 September outage with an
    extra step.
    """
    both = {
        "real.sh": "run_install() { :; }\n",
        "caller.sh": 'payload="$(declare -f run_install)"\nrun_install\n',
    }
    missing, _ = analyse(both)
    assert [(m.line, m.name) for m in missing if m.script == "caller.sh"] == [
        (2, "run_install")]


def test_an_unfollowable_source_is_reported_rather_than_assumed_empty():
    """"I could not read it" must not arrive as "there is nothing in it"."""
    missing, opaque = analyse({"main.sh": 'source "$SOME_RUNTIME_PATH"\nhelper\n'})
    assert [(o.script, o.line, o.raw) for o in opaque] == [
        ("main.sh", 1, '"$SOME_RUNTIME_PATH"')]
    assert [m.name for m in missing] == ["helper"]


# --- the outage this file was written for ----------------------------------

#: The commit that shipped case 3. Its `deploy/install.sh` calls
#: `migrate_legacy_state_markers` at line 5586 — the exact line the Ubuntu
#: host reported as `command not found`.
CASE_THREE_COMMIT = "8ca6e5b"
CASE_THREE_SYMBOLS = {"migrate_legacy_state_markers": 5586,
                      "ensure_state_markers_dir": 5587}


@needs_git
def test_the_commit_that_killed_the_ubuntu_deploy_is_caught():
    """The proof that this test would have stopped the outage it cites.

    Not a reconstruction: the real tree of the real commit, analysed by the
    same `analyse()` the gate above calls. If this passes while the gate is
    green on HEAD, the gate is doing something.
    """
    reachable = subprocess.run(
        [_GIT, "-C", str(REPO), "cat-file", "-e", f"{CASE_THREE_COMMIT}^{{commit}}"],
        capture_output=True)
    if reachable.returncode != 0:
        pytest.skip(f"CHECK DID NOT RUN: commit {CASE_THREE_COMMIT} is not in "
                    "this clone (shallow, or history rewritten), so the one "
                    "outage this file cites was NOT replayed. "
                    "test_scanner_reports_a_call_in_every_command_position "
                    "still covers the mechanism; this specific proof did not run.")

    missing, _ = analyse(_texts_at(CASE_THREE_COMMIT))
    found = {m.name: m.line for m in missing if m.script == "deploy/install.sh"}
    assert found == CASE_THREE_SYMBOLS, (
        f"in {CASE_THREE_COMMIT} the installer calls two functions defined only "
        "in an uncommitted deploy/lib/common.sh; this check must name both, at "
        f"their committed lines. It reported: {found}")
