"""A remediation line must name a command the host will actually accept.

The operator-visible failure this file exists to prevent: an alert fires at
3 a.m., the operator types the command the alert told them to type, and the
host answers

    sentinel scan: unrecognised argument(s): --now
    Refusing to run: an unknown flag is not permission to fall through to the
    default action.

Two of those shipped — `sentinel scan --now` and `sentinel maintenance
--prune`, both in `sentinel/selfcheck/checks.py`. Neither flag has ever
existed. The refusal itself is correct and deliberate (see
`sentinel.services.parse_service_args`: a flag nobody parses used to mean
"start the daemon", which is how `sentinel telegram --send-test` started a
second long-poller against a live token). The defect is that the one line the
operator is given to type, at the moment a scanner is already degraded, is
wrong — and nothing between writing it and reading it on the phone ever
compared it against a parser.

## Why this asks the parsers instead of listing them

A hand-written table of "flags each service defines" is the thing that rots:
it is correct on the day it is written and silently wrong after the first
service that gains or loses an option. So the expected set is taken from the
REAL parser of the REAL service, at test time.

The seam is `parse_service_args`. Every service module imports it by name and
calls it as the first thing `main()` does, after building its parser and
before starting anything. Replacing that name with a spy therefore hands us
the parser the service actually built, and stops `main()` dead before a daemon
or an account command runs. The same seam is already used by
`tests/unit/test_cli_service_args.py::test_documented_service_flags_are_really_parsed`.

What stops a service from actually RUNNING inside this test process is the
spy, and only the spy: it raises before `main()` reaches its first statement
after parsing. Measured across all 14 services with the seam in place —
`asyncio.run`, `socket.bind`, `socket.connect`, `subprocess.run`,
`subprocess.Popen`, `get_config` and `get_secrets` are called zero times.

The argv below (`--flag-no-service-can-define`) is the SECOND line, for the
case where a service has left the seam, and it holds only as long as the
shipped parser stays STRICT. That is not hypothetical: reverted to the
historical lenient `parse_known_args`, `telegram`'s `main()` walks straight
past the unknown flag and reaches `get_config()`. So the guarantee is "the spy
contains it; if the seam is gone, argparse contains it, as long as
`parse_service_args` still refuses what it does not recognise" — which is
itself pinned, at the bottom of this file, by
`test_the_service_really_refuses_the_flag_the_alert_used_to_name`.

If a service ever stops going through that seam, the spy never fires and this
file FAILS rather than reporting an empty flag set — "I could not read the
parser" and "the parser defines no flags" are different states, and `ingest`
and `detect` legitimately define none.

The commands the dispatcher keeps for itself (`migrate`, `config-check`,
`version`) are read from `sentinel.__main__.build_parser()`, which is where
their flags really live.

## What is scanned, and what deliberately is not

* every string literal in the Python under `sentinel/` — read through the AST,
  so an alert string, a `print()` to the operator and a docstring are all
  covered;
* every non-comment line of the shell under `deploy/` and `scripts/` — the
  installer does not merely advise these commands, it RUNS them;
* the operator-facing text of the dashboard templates under
  `sentinel/web/templates/`. `sentinel/` used to mean `*.py` under `sentinel/`,
  which quietly left four commands unscanned — `--set-password`,
  `--revoke-sessions` and `--enroll-totp` in `account.html` and `login.html`,
  and `systemctl status sentinel-maintenance.service` in `reports.html`. They
  are printed inside `<code>` blocks, they ship as `package-data` in
  `pyproject.toml`, and they are the same "type this" surface as an alert:
  `--set-password` renamed to `--set-passwd` used to pass every test in the
  repository.

Comments are out, in all three languages, and that is load-bearing rather than
lazy: `sentinel/__main__.py` explains the dispatcher bug by naming `sentinel
migrate --dry-runn`, a flag that must never exist, and `deploy/install.sh`
discusses `--send-test` in prose. A comment is not what the operator types at
3 a.m. Including them would make this test red on correct code, and a test
that is red on correct code is the next one somebody weakens.

`docs/` is out too, and the reason given here used to be that
`docs/CHANGELOG.md` records flags that were RETIRED. Measured, that is not what
happens: across the whole of `docs/` the scan finds zero invocations naming a
command or a flag that does not exist. The one real hit is a unit —
`sentinel-canary`, `docs/TESTARE.md:169` — and it is the actual reason.
That line tells a tester to create a throwaway unit by hand, stop it, and watch
an availability incident open and close; `deploy/systemd/` does not ship it and
must not. Documentation is where drill scaffolding, hypotheticals and history
legitimately live, a scanner cannot tell those from a defect, and what this
file guards is what an ALERT tells the operator to type — not what a manual
explains.

## Units

`systemctl start sentinel-scan` naming a unit `deploy/systemd/` does not ship
is the same defect wearing different clothes, and it is already here once:
`journalctl -u sentinel-migrate` points at a unit that does not exist (there
is no migrate daemon — `sentinel migrate` is a foreground command that writes
to stderr), so the operator gets an empty journal and no hint why.

Only `sentinel*` units are asserted. Whether the host has `postgresql.service`
or `nginx.service` is not something this repository can know, and this file
does not pretend otherwise: those references are left unjudged rather than
reported as fine.

### Where the unit names really come from

Scanning strings is not enough, and believing it was is how this file shipped
with a coverage claim it could not back. `check_units` and `check_timers` build
their actions by interpolation — `action=f"journalctl -u {unit} -n 50"` — and
the AST hands a scanner `"journalctl -u "` and `" -n 50"` as two separate
constants. No unit name is ever seen. Proven: adding `sentinel-migrate.service`
to `SYSTEMD_UNITS`, and renaming a timer to `sentinel-scanner.timer`, passed
all 5108 tests.

So the LISTS are checked, not the strings they render into:
`sentinel.constants.SYSTEMD_UNITS` and `sentinel.selfcheck.checks.
SELFCHECK_TIMERS`. That is worth more than the string check ever was —
`check_units` runs `systemctl is-active` on every entry, so a name that drifted
from `deploy/systemd/` is a permanent false `down` on a unit that does not
exist, PLUS an action that prints an empty journal. And because a list can be
escaped by being inlined back into the loop header, this file also runs the two
functions against a stubbed `systemctl` and compares the units they REALLY
probed with the ones the lists declare.

That comparison used to be an AST read of the loop header — `loops[0].iter` is
an `ast.Name` whose `id` is the list's name — and it was the wrong shape twice
over. It checked the NAME, not the list: a local `SELFCHECK_TIMERS = (...)`
declared inside `check_timers` shadows the constant, the loop header still
reads `SELFCHECK_TIMERS`, and the whole suite stayed green while the check
probed two units `deploy/systemd/` does not ship and never probed five real
timers. And it went red on CORRECT code: a second, harmless `for` loop
anywhere in either function tripped the "exactly one loop" assertion, and a
test that is red on correct code is the next one somebody weakens. The probe
below is immune to shadowing, aliasing, `tuple()`, a comprehension and an
extra loop alike, because it looks at what reached `systemctl`.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import html
import importlib
import re
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel import __main__ as cli
from sentinel.constants import SYSTEMD_UNITS
from sentinel.selfcheck import checks as selfcheck_checks
from sentinel.selfcheck.checks import SELFCHECK_TIMERS

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD_DIR = ROOT / "deploy" / "systemd"
TEMPLATE_DIR = ROOT / "sentinel" / "web" / "templates"

# Funcție de selfcheck -> (numele listei, lista) peste care ITEREAZĂ. Perechea
# e verificată în amândouă sensurile mai jos: numele din listă trebuie să fie
# livrate de `deploy/systemd/`, iar funcția trebuie să itereze chiar lista asta.
# Un tuplu scris înapoi în antetul buclei ar scoate verificarea din joc fără să
# schimbe nimic vizibil.
UNIT_SOURCE_LISTS = {
    "check_units": ("SYSTEMD_UNITS", SYSTEMD_UNITS),
    "check_timers": ("SELFCHECK_TIMERS", SELFCHECK_TIMERS),
}


# ---------------------------------------------------------------------------
# What the shipped parsers really define
# ---------------------------------------------------------------------------
class _ParserCaptured(BaseException):
    """Carries the parser the service really built, and stops main() there.

    Derived from BaseException, not Exception, on purpose: several services
    wrap their body in `except Exception`, and a spy that could be swallowed
    would leave this file believing the service defines no flags — which is a
    legal answer for `ingest` and `detect`, so the lie would look plausible.
    """

    def __init__(self, parser: argparse.ArgumentParser) -> None:
        self.parser = parser


def _service_flags(name: str) -> frozenset[str]:
    """Every option string `sentinel <name>` accepts, from its own parser."""
    module = importlib.import_module(f"sentinel.services.{name}_service")
    real = getattr(module, "parse_service_args", None)
    assert real is not None, (
        f"{name} no longer imports parse_service_args; this file can no longer "
        f"read its flags and must not guess them")

    def spy(parser: argparse.ArgumentParser, argv):
        raise _ParserCaptured(parser)

    setattr(module, "parse_service_args", spy)
    try:
        # A flag no service can define, not an empty argv. With the seam in
        # place the spy fires first and the argument is never looked at; with
        # the seam GONE — which is the case this has to survive — argparse's
        # own error is what stops `main()` before it starts a daemon inside the
        # test process, AS LONG AS the parser is still strict. An empty argv,
        # on a service that had left the seam, would start the long-poller or
        # bind the web server right here: the exact hazard `parse_service_args`
        # exists to prevent, reproduced by the file that checks it. See the
        # module docstring for what each of the two lines actually covers, and
        # for the measurement showing the lenient parser is not covered at all.
        module.main(["--flag-no-service-can-define"])
    except _ParserCaptured as captured:
        # `_option_string_actions` is argparse's own index of every accepted
        # option string. Private, but it is the mapping argparse itself uses to
        # decide, so it cannot disagree with what the service will accept.
        return frozenset(captured.parser._option_string_actions)
    except SystemExit as stopped:
        raise AssertionError(
            f"sentinel {name}: main() parsed its arguments without going "
            f"through parse_service_args (argparse exited {stopped.code}), so "
            f"its flags could not be read") from stopped
    finally:
        setattr(module, "parse_service_args", real)
    raise AssertionError(
        f"sentinel {name}: main() returned without going through "
        f"parse_service_args, so its flags could not be read")


def _dispatcher_subparsers() -> dict[str, argparse.ArgumentParser]:
    for action in cli.build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    raise AssertionError(
        "the dispatcher no longer registers subcommands; the command list "
        "below would be empty and every assertion in this file vacuous")


def known_flags() -> dict[str, frozenset[str]]:
    """command -> the option strings it accepts, asked of the shipped code."""
    table: dict[str, frozenset[str]] = {}
    for command, sub in _dispatcher_subparsers().items():
        # Service subcommands are registered with no arguments of their own so
        # that argparse does not reject a service's flags before the service
        # sees them. Their real flags live in the service module.
        table[command] = (_service_flags(command) if command in cli.SERVICES
                          else frozenset(sub._option_string_actions))
    return table


# ---------------------------------------------------------------------------
# What the sources tell the operator to type
# ---------------------------------------------------------------------------
_INVOCATION = re.compile(
    r"\bsentinel[ \t]+(?P<cmd>[a-z][a-z0-9-]*)"
    r"(?P<flags>(?:[ \t]+\[?--[a-z0-9][a-z0-9-]*\]?)+)")
# `[--message]`, as the CLI usage lines write an optional flag.
_FLAG = re.compile(r"--[a-z0-9][a-z0-9-]*")

_SYSTEMCTL_UNIT = re.compile(
    r"\bsystemctl[ \t]+(?:--[a-z-]+[ \t]+)*[a-z][a-z-]*[ \t]+"
    r"(?P<unit>sentinel[a-z0-9@_.-]*)")
_JOURNALCTL_UNIT = re.compile(
    r"\bjournalctl[ \t]+(?:[^ \t]+[ \t]+)*?-u[ \t]+"
    r"(?P<unit>sentinel[a-z0-9@_.-]*)")

# Numit, fiindcă fiecare tipar trebuie să-și dovedească singur că vede ceva.
# Un prag comun („cel puțin 40 de referințe") e trecut de oricare dintre ele de
# unul singur: măsurat, systemctl dă 43 de referințe și journalctl 65, deci
# orbirea fiecăruia pe rând a lăsat suita verde. Ăsta e exact defectul din
# CLAUDE.md — „grep după un tipar care nu există" — reprodus în fișierul scris
# ca să-l prevină, iar defectul de la care a pornit tot, `journalctl -u
# sentinel-migrate`, era o referință de `journalctl`.
UNIT_PATTERNS = {"systemctl": _SYSTEMCTL_UNIT, "journalctl": _JOURNALCTL_UNIT}


@dataclass(frozen=True)
class Invocation:
    where: str
    command: str
    flags: tuple[str, ...]


@dataclass(frozen=True)
class UnitRef:
    where: str
    unit: str
    via: str        # tiparul care l-a găsit: "systemctl" sau "journalctl"


def _python_operator_strings() -> list[tuple[str, str]]:
    """(where, text) for every string literal under `sentinel/`.

    Read from the AST rather than the raw file so that comments cannot make
    this test red — see the module docstring for why that is deliberate.
    Adjacent literals are folded by the parser into one constant, so an action
    split across two source lines is still seen whole.

    The pieces of an f-string arrive SEPARATELY, and that is a real gap, not a
    theoretical one. No flag name is interpolated, so the flag half of this
    file is whole. Unit names are — `f"journalctl -u {unit} -n 50"` gives this
    function `"journalctl -u "` and `" -n 50"` and no name at all — which is
    why the unit half does not rely on these strings alone and checks
    `UNIT_SOURCE_LISTS` instead. See the module docstring, "Where the unit
    names really come from".
    """
    out: list[tuple[str, str]] = []
    for path in sorted((ROOT / "sentinel").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                out.append((f"{rel}:{node.lineno}", node.value))
    return out


def strip_shell_comment(line: str) -> str:
    """The part of a shell line the shell will actually execute.

    Whole-line `#` was all that used to be dropped, which left this file able to
    go red on CORRECT code: appending a trailing `# istoric: sentinel scan
    --now a fost eliminat` to any shell script turned the suite red, and the
    cheapest way out of a test that is red on correct code is to weaken it.

    Where the comment starts is decided the way the shell decides it, not by the
    first `#` on the line — a naive cut would swallow real code and make this
    scan silently blind, which is the more expensive direction of the same
    mistake. A hash opens a comment only when it is unquoted and starts a word,
    which is what keeps `${VAR#prefix}`, `$#`, `--format=%H` and a hash inside
    `'...'` or `"..."` intact.
    """
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and quote != "'":
            i += 2                      # escaped: the next character is literal
            continue
        if quote is None:
            if ch in "'\"":
                quote = ch
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                return line[:i]
        elif quote == ch:
            quote = None
        i += 1
    return line


def _shell_operator_strings() -> list[tuple[str, str]]:
    """(where, text) for the executable part of every line of shell."""
    out: list[tuple[str, str]] = []
    paths = [*(ROOT / "deploy").rglob("*.sh"), *(ROOT / "scripts").rglob("*.sh")]
    for path in sorted(paths):
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="strict")
        for lineno, line in enumerate(text.splitlines(), start=1):
            code = strip_shell_comment(line)
            if code.strip():
                out.append((f"{rel}:{lineno}", code))
    return out


# `{# ... #}` și `{% ... %}` sunt ale motorului de șabloane, nu ale
# operatorului, iar un `<b>` în mijlocul unei comenzi ar rupe-o în două pentru
# tiparele de mai sus. Toate se șterg păstrând liniile, ca numărul din `where`
# să rămână chiar cel din fișier — o trimitere greșită la 3 dimineața costă mai
# mult decât potrivirea pe care o raportează.
_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.DOTALL)
_JINJA_BLOCK = re.compile(r"\{%.*?%\}", re.DOTALL)
_JINJA_VAR = re.compile(r"\{\{.*?\}\}", re.DOTALL)
_HTML_TAG = re.compile(r"<[^>]*>", re.DOTALL)

#: Ce rămâne în locul unei interpolări de o singură linie. Nu un șir gol:
#: ștergerea ar lipi textul din stânga de cel din dreapta și ar putea fabrica un
#: nume de unitate (`sentinel-{{ x }}` -> `sentinel-`) pe care `deploy/systemd/`
#: n-are cum să-l livreze, adică roșu pe markup corect. Acoladele nu fac parte
#: nici din clasa de caractere a unui flag, nici din a unui nume de unitate,
#: deci un nume care atinge o interpolare se oprește acolo, iar `find_unit_refs`
#: îl lasă nejudecat în loc să-l raporteze.
TEMPLATE_PLACEHOLDER = "{}"


def _blank_keeping_lines(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _mark_interpolation(match: re.Match[str]) -> str:
    text = match.group(0)
    if "\n" in text:
        return _blank_keeping_lines(match)
    return TEMPLATE_PLACEHOLDER + " " * (len(text) - len(TEMPLATE_PLACEHOLDER))


def template_text(raw: str) -> str:
    """Șablonul, redus la ce chiar citește operatorul pe ecran.

    Numărul de linii se păstrează de cele patru substituiri, care înlocuiesc
    fiecare caracter cu un spațiu în loc să-l șteargă — de-asta `where` arată
    chiar linia din fișier, iar o trimitere greșită la 3 dimineața costă mai
    mult decât potrivirea pe care o raportează.

    NU de dezescaparea pe linii. Motivul scris aici până pe 15 septembrie 2026
    spunea că despicarea pe linii e cea care oprește un `&#10;` să decaleze
    numerele; e fals, și se verifică în două linii: `html.unescape` pe tot
    textul și pe fiecare linie în parte dau exact aceiași octeți, iar amândouă
    mută numărul de linii (3 brute -> 4). Niciun șablon livrat nu conține o
    astfel de entitate, deci decalajul e teoretic; ce nu e teoretic e un
    comentariu care explică o apărare inexistentă și-l face pe următorul să
    creadă că e acoperit. Comportamentul rămâne neschimbat.
    """
    text = _JINJA_COMMENT.sub(_blank_keeping_lines, raw)
    text = _JINJA_BLOCK.sub(_blank_keeping_lines, text)
    text = _JINJA_VAR.sub(_mark_interpolation, text)
    text = _HTML_TAG.sub(_blank_keeping_lines, text)
    return "\n".join(html.unescape(line) for line in text.splitlines())


def _template_operator_strings() -> list[tuple[str, str]]:
    """(where, text) for every line of dashboard markup the operator reads.

    The templates ship as `package-data` and print commands to the operator
    inside `<code>` blocks; see the module docstring for the four that were
    invisible until this existed.
    """
    out: list[tuple[str, str]] = []
    for path in sorted(TEMPLATE_DIR.rglob("*.html")):
        rel = path.relative_to(ROOT).as_posix()
        text = template_text(path.read_text(encoding="utf-8", errors="strict"))
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.strip():
                out.append((f"{rel}:{lineno}", line))
    return out


def _sources() -> list[tuple[str, str]]:
    return [*_python_operator_strings(), *_shell_operator_strings(),
            *_template_operator_strings()]


def find_invocations(sources: list[tuple[str, str]]) -> list[Invocation]:
    return [Invocation(where, m.group("cmd"),
                       tuple(_FLAG.findall(m.group("flags"))))
            for where, text in sources
            for m in _INVOCATION.finditer(text)]


def find_unit_refs(sources: list[tuple[str, str]]) -> list[UnitRef]:
    found: list[UnitRef] = []
    for where, text in sources:
        for via, pattern in UNIT_PATTERNS.items():
            for m in pattern.finditer(text):
                # Un nume tăiat de o interpolare de șablon nu se poate judeca:
                # numele adevărat se compune la randare și n-a fost văzut aici
                # niciodată. Nu e „e în regulă", e „nu l-am citit" — deci nu
                # intră nici în lista comparată cu `deploy/systemd/`, nici în
                # praguri, ca un prag să nu se umple cu ce nu s-a citit.
                if text[m.end("unit"):m.end("unit") + 1] == "{":
                    continue
                # A name at the end of a sentence keeps the full stop; no unit
                # file ends in one.
                found.append(UnitRef(where, m.group("unit").rstrip("."), via))
    return found


def unit_is_shipped(ref: str) -> bool:
    """systemd's own rule: a bare name means `.service`."""
    if ref.endswith((".service", ".timer", ".socket", ".path")):
        return (SYSTEMD_DIR / ref).is_file()
    return (SYSTEMD_DIR / f"{ref}.service").is_file()


# ---------------------------------------------------------------------------
# The scan sees something (nothing below is evidence otherwise)
# ---------------------------------------------------------------------------
def test_the_flag_table_covers_every_command_the_dispatcher_routes():
    """A parser this file cannot read is reported as unreadable, not as empty.

    If the seam broke and every command came back with no flags, the class
    test below would pass by finding nothing to compare — the shape of
    "verified" that has cost this repository outages before.
    """
    table = known_flags()
    assert set(table) >= set(cli.SERVICES), \
        f"commands missing from the table: {set(cli.SERVICES) - set(table)}"
    assert {"migrate", "config-check", "version"} <= set(table)


def test_the_flag_table_is_the_one_the_services_really_have():
    """Pinned against the live parsers, including the flag from the bug.

    `--now` is not in `scan`'s parser and never was; if it ever appears here,
    the introspection has stopped reading the shipped code and has started
    agreeing with whatever the alert says.
    """
    table = known_flags()
    assert "--log-level" in table["scan"]
    assert "--now" not in table["scan"], \
        "scan --now suddenly exists; the spy is reading the wrong parser"
    assert "--prune" not in table["maintenance"]
    assert {"--create-admin", "--enroll-totp", "--username"} <= table["web"]
    assert {"--print", "--quiet"} <= table["selfcheck"]
    assert "--reapply" in table["reconcile"]
    assert {"--rollup", "--probe-only", "--capacity-only"} <= table["health"]
    assert {"--send-test", "--message"} <= table["telegram"]
    assert "--dry-run" in table["migrate"]
    # Two services deliberately define nothing. Empty here is a fact, not a
    # failure to read — which is exactly why the seam must fail loudly instead
    # of returning an empty set when it cannot see the parser.
    assert table["detect"] == frozenset()


def test_the_source_scan_actually_finds_invocations():
    """A regex that matches nothing satisfies every assertion made about it.

    This repository has shipped exactly that: a check grepping for a log
    pattern that never existed, reporting "nothing wrong" forever.
    """
    found = find_invocations(_sources())
    assert len(found) >= 15, \
        f"only {len(found)} invocations found; the scan or the sources changed"
    pairs = {(i.command, i.flags) for i in found}
    assert ("web", ("--create-admin",)) in pairs
    assert ("telegram", ("--send-test",)) in pairs
    # All three file kinds must be contributing, or part of the scan is asleep.
    assert any(".py:" in i.where for i in found), "no Python source contributed"
    assert any(".sh:" in i.where for i in found), "no shell source contributed"
    assert any(".html:" in i.where for i in found), \
        "no dashboard template contributed"


def test_the_template_scan_actually_reads_the_dashboard():
    """Four commands the operator is told to type lived outside every scan.

    What breaks for the operator if this goes vacuous: the account page tells
    them to run `sentinel web --set-password --username <name>` to reset a
    password they have lost. If that flag is renamed and nothing compares the
    page against the parser, the page keeps printing the old one and the host
    answers `unrecognised argument(s)`. Renaming it to `--set-passwd` used to
    pass every test in this repository.

    Pinned to the two flags and the one unit the dashboard prints today. If a
    page legitimately stops printing commands, this assertion is what forces
    somebody to look at whether the facet still has anything to scan, rather
    than letting it quietly scan nothing.
    """
    lines = _template_operator_strings()
    assert lines, f"{TEMPLATE_DIR} produced no lines at all"
    pairs = {(i.command, i.flags) for i in find_invocations(lines)}
    assert ("web", ("--set-password", "--username")) in pairs
    assert ("web", ("--enroll-totp", "--username")) in pairs
    assert any(u.unit == "sentinel-maintenance.service"
               for u in find_unit_refs(lines)), \
        "the dashboard no longer names a systemd unit; check the facet is alive"


def test_the_template_reader_sees_through_markup_and_leaves_jinja_alone():
    """Fixed input, so this keeps proving the reader works after the pages change.

    What breaks if it is wrong in one direction: a command split by `<b>` tags,
    or written with `&lt;user&gt;`, is never seen and a renamed flag ships. In
    the other direction: `{{ ... }}` is a value the server fills in at render
    time, and treating it as literal text would report a unit or a flag nobody
    ever types — a red on correct markup, which is the kind of test that gets
    weakened rather than fixed.
    """
    seen = template_text(
        "<p>Rulează <code>sentinel web --enroll-totp --username "
        "&lt;user&gt;</code></p>")
    assert "sentinel web --enroll-totp --username <user>" in seen
    assert "<code>" not in seen and "&lt;" not in seen

    # Jinja: comment and block out, interpolation marked rather than deleted.
    assert "sentinel scan --now" not in template_text(
        "{# istoric: sentinel scan --now a fost eliminat #}")
    # `{% ... %}` is the engine's own syntax and goes; the text it guards is
    # still printed to the operator when the branch is taken, so it STAYS
    # scannable. Dropping it would be the silent-blindness direction again.
    conditional = template_text(
        "{% if user.is_admin %}sentinel web --create-admin{% endif %}")
    assert "{%" not in conditional and "endif" not in conditional
    assert ("web", ("--create-admin",)) in {
        (i.command, i.flags)
        for i in find_invocations([("x.html:1", conditional)])}
    marked = template_text("systemctl status sentinel-{{ unit }}.service")
    assert TEMPLATE_PLACEHOLDER in marked
    # …and a name cut by an interpolation is left unjudged, not reported.
    assert find_unit_refs([("x.html:1", marked)]) == []

    # Line numbers must survive every one of those substitutions, or the alert
    # sends the operator to the wrong line of the wrong page.
    multi = template_text("<p>a</p>\n{# b\n   c #}\n<code>{{ d }}</code>\ne")
    assert len(multi.splitlines()) == 5


def test_the_matcher_recognises_the_shapes_it_has_to_recognise():
    """Proof against the two real defects and the forms around them.

    Written as fixed input rather than repository text so that it keeps
    proving the matcher works after the repository is repaired — otherwise the
    only evidence that this file can catch the bug disappears with the bug.
    """
    samples = [
        # The two that shipped.
        ("journalctl -u sentinel-scan -n 50 ; sentinel scan --now",
         [("scan", ("--now",))]),
        ("Verifică retenția: sentinel maintenance --prune",
         [("maintenance", ("--prune",))]),
        # Forms that must not be missed.
        ("sudo -u sentinel sentinel selfcheck --print",
         [("selfcheck", ("--print",))]),
        ("/opt/sentinel/bin/sentinel telegram --send-test",
         [("telegram", ("--send-test",))]),
        ("sentinel web --enroll-totp --username <utilizator>",
         [("web", ("--enroll-totp", "--username"))]),
        ("sentinel telegram --send-test [--message TEXT]",
         [("telegram", ("--send-test", "--message"))]),
        # Not an invocation: a unit name is not a subcommand.
        ("journalctl -u sentinel-ingest -n 50", []),
    ]
    for text, expected in samples:
        got = [(i.command, i.flags) for i in find_invocations([("x:1", text)])]
        assert got == expected, f"matcher read {text!r} as {got}"


# ---------------------------------------------------------------------------
# The class test
# ---------------------------------------------------------------------------
def test_every_command_named_in_an_operator_string_exists():
    """`sentinel prune --all` would be refused with EX_CONFIG, not run.

    Same 3 a.m., same operator, one step earlier than a wrong flag.
    """
    table = known_flags()
    offenders = [f"{i.where}: sentinel {i.command} {' '.join(i.flags)}"
                 for i in find_invocations(_sources()) if i.command not in table]
    assert not offenders, (
        "command that `sentinel` does not have:\n  " + "\n  ".join(offenders)
        + f"\n  Known: {', '.join(sorted(table))}")


def test_every_flag_named_in_an_operator_string_is_defined_by_that_command():
    """The bug itself: the alert names a flag, the service refuses it.

    `parse_service_args` exits 64 and starts nothing — correctly. So the
    operator, woken by a degraded scanner, types the one line they were given
    and gets a usage message instead of a scan.
    """
    table = known_flags()
    offenders = []
    for inv in find_invocations(_sources()):
        if inv.command not in table:
            continue  # reported by the test above
        for flag in inv.flags:
            if flag not in table[inv.command]:
                offenders.append(
                    f"{inv.where}: `sentinel {inv.command} {flag}` — "
                    f"{inv.command} accepts "
                    f"{', '.join(sorted(table[inv.command])) or '(no flags)'}")
    assert not offenders, (
        "operator instructions naming a flag the service refuses:\n  "
        + "\n  ".join(offenders))


# ---------------------------------------------------------------------------
# The same defect, wearing a unit name
# ---------------------------------------------------------------------------
#: Prag per tipar: (referințe, nume distincte). Măsurat pe depozit înainte de
#: orice schimbare din runda asta — systemctl 43/17, journalctl 65/12 — deci
#: pragurile nu se sprijină pe ce tocmai s-a adăugat. Marja e largă dinadins:
#: un prag lipit de măsurătoare devine roșu la prima ștergere legitimă a unei
#: acțiuni, iar un test roșu pe cod corect e următorul care se slăbește.
UNIT_PATTERN_FLOORS = {"systemctl": (30, 10), "journalctl": (40, 8)}

#: Forma pe care fiecare tipar există ca s-o vadă, și numai el. Fixă, nu luată
#: din surse: un eșantion cules din repository ar dispărea odată cu ultima
#: referință și ar lăsa aserțiunea de mai jos fără nimic de verificat.
UNIT_PATTERN_SAMPLES = {
    "systemctl": "systemctl restart sentinel-scan.service",
    "journalctl": "journalctl -u sentinel-scan.service -n 50",
}


def test_neither_unit_pattern_can_stand_in_for_the_other():
    """Două praguri separate peste același tipar nu mai verifică două lucruri.

    What breaks for the operator: `_JOURNALCTL_UNIT = _SYSTEMCTL_UNIT` passes
    all 5120 tests. The floors above are cleared either way, because the label
    on a reference comes from the dict key, not from the tool the pattern
    matched — so both halves of the scan would be counting `systemctl` lines
    and reporting one of them as `journalctl` coverage. The defect this whole
    file exists for, `journalctl -u sentinel-migrate`, is a `journalctl`
    reference: the operator is sent to an empty journal and concludes the
    service logged nothing.
    """
    assert set(UNIT_PATTERN_SAMPLES) == set(UNIT_PATTERNS), (
        "a unit pattern has no sample of its own, so it could be replaced by "
        f"another unnoticed: {set(UNIT_PATTERNS) ^ set(UNIT_PATTERN_SAMPLES)}")
    for via, sample in UNIT_PATTERN_SAMPLES.items():
        m = UNIT_PATTERNS[via].search(sample)
        assert m and m.group("unit") == "sentinel-scan.service", (
            f"`{via}` no longer matches its own form: {sample!r}")
        for other, pattern in UNIT_PATTERNS.items():
            if other == via:
                continue
            assert not pattern.search(sample), (
                f"`{other}` matches a `{via}` invocation, so the two patterns "
                f"are no longer telling the two tools apart and one of them "
                f"could be deleted without a single test noticing")


def test_each_unit_pattern_finds_units_on_its_own():
    """Half this scan can die without a single test noticing. That is the bug.

    What breaks for the operator: `journalctl -u sentinel-migrate` — the defect
    that made this whole file exist — was a `journalctl` reference. A single
    floor over both patterns is cleared by EITHER of them alone (43 and 65
    references, measured), so blinding `_JOURNALCTL_UNIT` on its own left all
    13 tests here green while the check silently stopped checking the half it
    was written for. Same shape as the check in this repository that grepped a
    log pattern which never existed and reported "nothing wrong" forever.
    """
    found = find_unit_refs(_sources())
    assert len(found) >= 40, \
        f"only {len(found)} unit references found; the scan or the sources changed"
    assert set(UNIT_PATTERN_FLOORS) == set(UNIT_PATTERNS), (
        "a unit pattern exists with no floor of its own, so it could match "
        f"nothing unnoticed: {set(UNIT_PATTERNS) ^ set(UNIT_PATTERN_FLOORS)}")
    for via, (min_refs, min_names) in UNIT_PATTERN_FLOORS.items():
        refs = [u for u in found if u.via == via]
        names = {u.unit for u in refs}
        assert len(refs) >= min_refs, (
            f"`{via}` matched {len(refs)} references on its own; it is either "
            f"broken or the sources stopped using it")
        assert len(names) >= min_names, (
            f"`{via}` produced {len(names)} distinct unit names; a pattern that "
            f"only ever matches the same one is barely matching")
    # Pinned per pattern, not over the union: a name that only one of them can
    # reach is the whole point of asking them separately.
    by_systemctl = {u.unit for u in found if u.via == "systemctl"}
    by_journalctl = {u.unit for u in found if u.via == "journalctl"}
    assert {"sentinel-scan", "sentinel-maintenance"} <= by_systemctl
    assert {"sentinel-scan", "sentinel-ingest"} <= by_journalctl


#: The verb whose argument is the unit name. Both self-checks ask the same
#: question first — "is this thing running" — and every other `systemctl` call
#: they make (`show -p NRestarts --value`) puts the unit in the middle of the
#: argv, so picking the last argument off blind would record a flag as a unit.
_LIVENESS_VERB = "is-active"


def _units_really_probed(func_name: str) -> set[str]:
    """The units `func_name` actually handed to `systemctl is-active`.

    Not what its loop header is spelled like — what reached the process. A
    local list shadowing the module constant, an alias, a `tuple()`, a
    comprehension or a second loop all change this set; none of them change the
    name in the loop header, which is what this file used to read.

    Everything in the config is enabled, so nothing is legitimately skipped:
    `check_units` drops `sentinel-ai` and `sentinel-beacon` when those are off,
    and a probe run with them off would compare a short list against a full one
    and report a drift that is not there.
    """
    seen: list[tuple[str, ...]] = []

    def _spy(*args: str) -> str:
        seen.append(args)
        return "active"          # ca ambele funcții să ia ramura „ok"

    cfg = SimpleNamespace(ai=SimpleNamespace(enabled=True),
                          beacon=SimpleNamespace(enabled=True))
    func = getattr(selfcheck_checks, func_name)
    real = selfcheck_checks._systemctl
    selfcheck_checks._systemctl = _spy
    try:
        asyncio.run(func(cfg))
    finally:
        selfcheck_checks._systemctl = real
    return {a[1] for a in seen if len(a) > 1 and a[0] == _LIVENESS_VERB}


def test_the_selfcheck_really_probes_the_units_these_lists_name():
    """Without this, the check below can be escaped without touching the list.

    What breaks for the operator: the list stays in the repository, correct and
    compared against `deploy/systemd/`, while the function probes a different
    one. MEASURED: a local `SELFCHECK_TIMERS = (...)` declared inside
    `check_timers` — which the AST guard this replaced read as "iterates
    SELFCHECK_TIMERS", because it read the NAME — left all 5120 tests green
    while the self-check reported two permanent false `down` findings on timers
    `deploy/systemd/` does not ship, and never once probed the five real ones.
    The operator sees two alarms that can never be cleared, and no coverage of
    the timers that actually run.
    """
    for func_name, (list_name, declared) in UNIT_SOURCE_LISTS.items():
        probed = _units_really_probed(func_name)
        assert probed, (
            f"{func_name} asked `systemctl {_LIVENESS_VERB}` about nothing; "
            f"either it stopped probing or it no longer uses that verb, and an "
            f"empty set would make the comparison below pass on nothing")
        assert probed == set(declared), (
            f"{func_name} really probes {sorted(probed)}, but {list_name} "
            f"declares {sorted(declared)}; the list this file checks against "
            f"deploy/systemd/ is not the one being used")


def test_every_unit_the_selfcheck_probes_is_one_deploy_ships():
    """A name in these lists is never seen as a string, and it costs twice.

    What breaks for the operator: `check_units` runs `systemctl is-active` on
    every entry and `check_timers` on every timer, and both build their action
    by interpolation — `f"journalctl -u {unit} -n 50"` — so no scanner of
    string literals ever sees the name. A drifted entry is therefore a
    permanent false `down` on a unit that does not exist, PLUS an action that
    prints an empty journal and explains nothing. Proven uncaught before this
    test: adding `sentinel-migrate.service` to `SYSTEMD_UNITS` and renaming a
    timer to `sentinel-scanner.timer` passed all 5108 tests.

    The floors below are the counts these two lists have had all along — seven
    services and seven timers — not counts introduced with this test.
    """
    assert len(SYSTEMD_UNITS) >= 7, "SYSTEMD_UNITS shrank; check why"
    assert len(SELFCHECK_TIMERS) >= 7, "SELFCHECK_TIMERS shrank; check why"
    offenders = []
    for func_name, (list_name, units) in UNIT_SOURCE_LISTS.items():
        assert units, (
            f"{list_name} is empty, so {func_name} probes nothing and this "
            f"assertion would pass by having nothing to check")
        for unit in units:
            if not unit_is_shipped(unit):
                offenders.append(f"{list_name} (read by {func_name}): {unit}")
    assert not offenders, (
        "the self-check probes a unit deploy/systemd/ does not ship, so it "
        "reports it `down` forever:\n  " + "\n  ".join(offenders))


def test_unit_is_shipped_can_tell_the_difference():
    """Without this, the test below passes by answering True to everything."""
    assert unit_is_shipped("sentinel-scan")
    assert unit_is_shipped("sentinel-scan.timer")
    assert not unit_is_shipped("sentinel-migrate")
    assert not unit_is_shipped("sentinel-scan.timer.timer")


def test_every_sentinel_unit_named_in_an_operator_string_is_shipped():
    """`journalctl -u sentinel-migrate` prints nothing and explains nothing.

    journalctl matches `-u` against the unit a message came from, so a name no
    unit file ever had returns an empty journal with exit 0. The operator, told
    to look at the logs of a failure, sees a clean screen and concludes the
    wrong thing.
    """
    offenders = sorted({f"{u.where}: {u.unit}" for u in find_unit_refs(_sources())
                        if not unit_is_shipped(u.unit)})
    assert not offenders, (
        "operator instructions naming a unit deploy/systemd/ does not ship:\n  "
        + "\n  ".join(offenders))


def test_a_trailing_shell_comment_is_not_an_instruction():
    """The inverse failure: this file going red on correct code.

    What breaks for the operator, eventually: somebody appends `# istoric:
    sentinel scan --now a fost eliminat` to an installer line, the suite goes
    red on a comment, and the fastest way to green is to delete an assertion
    from here. The scan that catches a real wrong flag dies of a comment.

    Fixed input on purpose, so it keeps proving the stripper works whatever the
    scripts happen to contain.
    """
    kept = "sentinel telegram --send-test"
    assert strip_shell_comment(f"  {kept}   # sentinel scan --now").strip() == kept
    assert strip_shell_comment("# whole line: sentinel maintenance --prune") == ""
    assert find_invocations(
        [("x.sh:1", strip_shell_comment("true  # sentinel scan --now"))]) == []
    assert find_unit_refs(
        [("x.sh:1", strip_shell_comment(
            "true  # journalctl -u sentinel-migrate -n 50"))]) == []


def test_the_shell_stripper_keeps_what_the_shell_would_run():
    """The other half: a hash is not always a comment, and cutting at the first
    one makes this whole scan silently blind.

    What breaks for the operator: `${VAR#prefix}` and `$#` are ordinary shell,
    and a hash inside quotes is data. Cutting there would drop the rest of the
    line — including any command on it — and the scan would report "nothing
    wrong" about text it never read. That is the exact disease this file is
    supposed to cure, so it is worth proving on fixed input.
    """
    samples = [
        ('sentinel web --create-admin --username "${U#pre}"',
         'sentinel web --create-admin --username "${U#pre}"'),
        ('echo "$# args" ; sentinel selfcheck --print',
         'echo "$# args" ; sentinel selfcheck --print'),
        ("grep '^history:' /etc/sentinel/sentinel.yaml",
         "grep '^history:' /etc/sentinel/sentinel.yaml"),
        ('echo "a # b" ; systemctl restart sentinel-ingest',
         'echo "a # b" ; systemctl restart sentinel-ingest'),
        ("journalctl -u sentinel-web -n 50#not-a-comment",
         "journalctl -u sentinel-web -n 50#not-a-comment"),
    ]
    assert samples, "empty sample list — the loop below would check nothing"
    for line, expected in samples:
        assert strip_shell_comment(line) == expected, f"mangled: {line!r}"
    # And the scan still sees what survived, or the assertions above prove
    # only that a string was copied.
    assert ("selfcheck", ("--print",)) in {
        (i.command, i.flags)
        for i in find_invocations([("x.sh:1", strip_shell_comment(samples[1][0]))])}


# ---------------------------------------------------------------------------
# The same defect, wearing a grep pattern
# ---------------------------------------------------------------------------
_CONFIG_GREP = re.compile(
    r"\bgrep[ \t]+(?:-[A-Za-z]+[0-9]*[ \t]+)*'(?P<pattern>\^[a-z_]+:)'"
    r"[ \t]+/etc/sentinel/sentinel\.yaml")

CONFIG_TEMPLATE = ROOT / "deploy" / "config" / "sentinel.yaml.tmpl"


def find_config_greps(sources: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(where, m.group("pattern"))
            for where, text in sources
            for m in _CONFIG_GREP.finditer(text)]


def test_the_config_grep_scan_actually_finds_greps():
    """Non-vacuity: the assertion below is worth nothing on an empty list.

    Pinned to `^history:`, which predates this file, rather than to the
    retention line repaired alongside it — a floor that counts the change that
    introduced it measures the change, not the scanner.
    """
    found = find_config_greps(_sources())
    assert len(found) >= 2, f"only {len(found)} config greps found"
    assert "^history:" in {p for _, p in found}


def test_every_config_section_an_action_greps_for_exists():
    """"Nothing matched" and "nothing is wrong" look identical on the console.

    A disc filling up tells the operator to read the retention settings. If the
    section were renamed, the grep would print nothing, exit 1, and the
    operator would be left thinking there are no retention settings at all —
    the same shape as the check that grepped a log pattern which never existed
    and reported "nothing wrong" forever.

    Checked against the shipped template, which is what the installer renders
    into `/etc/sentinel/sentinel.yaml`. It cannot speak for a file an operator
    has since hand-edited.
    """
    assert CONFIG_TEMPLATE.is_file(), f"{CONFIG_TEMPLATE} is missing"
    lines = CONFIG_TEMPLATE.read_text(encoding="utf-8").splitlines()
    offenders = sorted({
        f"{where}: {pattern}" for where, pattern in find_config_greps(_sources())
        if not any(re.search(pattern, line) for line in lines)})
    assert not offenders, (
        "operator instructions grepping for a section the shipped "
        f"configuration does not have:\n  " + "\n  ".join(offenders))


_CONFIG_GREP_AFTER = re.compile(
    r"\bgrep[ \t]+-A(?P<after>[0-9]+)[ \t]+'(?P<pattern>\^[a-z_]+:)'"
    r"[ \t]+/etc/sentinel/sentinel\.yaml")

#: Secțiune -> cheia pentru care acțiunea există. `grep -A<n>` se oprește după
#: n linii, iar o secțiune din șablonul ăsta e în majoritate comentariu: o
#: fereastră care „găsește secțiunea" poate foarte bine să nu ajungă niciodată
#: la valoarea pentru care operatorul a fost trimis acolo.
#:
#: Doar retenția e aici, dinadins. `^history:` are aceeași formă și, măsurat pe
#: gazdă, `grep -A3 '^history:'` chiar nu tipărește nicio valoare — numai trei
#: linii de comentariu. E un defect real, dar e al altei acțiuni și n-a fost
#: cerut acum; se raportează, nu se repară pe furiș aici.
GREP_MUST_REACH = {"^retention:": "disk_guard_free_pct"}

#: Câte linii de margine peste cheia țintă. Zero a fost starea de până acum și
#: e ce a produs problema: un singur comentariu adăugat în bloc scotea valoarea
#: din fereastră fără ca nimic să observe.
GREP_MARGIN_LINES = 5


def test_a_config_action_prints_the_setting_it_was_sent_to_show():
    """Fereastra `grep -A<n>` trebuie să AJUNGĂ la valoarea despre care e alerta.

    Ce se strică pentru operator: discul e la 92%, alerta îl trimite să citească
    retenția, iar `disk_guard_free_pct` — singura valoare din bloc care schimbă
    ceva pentru un disc plin — e exact ultima linie pe care `-A10` o mai
    tipărește. Măsurat în șablonul livrat și pe gazdă: `retention:` pe linia 54,
    `disk_guard_free_pct` pe 64. Un comentariu adăugat în bloc și operatorul
    primește o comandă care pare că merge și nu-i arată nimic — aceeași formă cu
    verificarea care căuta un tipar de jurnal ce nu exista și raporta „nimic în
    neregulă" la nesfârșit.
    """
    assert CONFIG_TEMPLATE.is_file(), f"{CONFIG_TEMPLATE} is missing"
    lines = CONFIG_TEMPLATE.read_text(encoding="utf-8").splitlines()
    found = [(where, int(m.group("after")), m.group("pattern"))
             for where, text in _sources()
             for m in _CONFIG_GREP_AFTER.finditer(text)]
    assert found, "no `grep -A<n>` over the configuration found at all"

    checked: set[str] = set()
    for where, after, pattern in found:
        key = GREP_MUST_REACH.get(pattern)
        if key is None:
            continue
        starts = [i for i, line in enumerate(lines) if re.search(pattern, line)]
        assert starts, f"{where}: `{pattern}` is not in the shipped template"
        start = starts[0]
        targets = [i for i, line in enumerate(lines[start:], start=start)
                   if line.strip().startswith(f"{key}:")]
        assert targets, (
            f"{where}: `{key}` is no longer in the shipped configuration, so "
            f"this action cannot print it whatever -A says")
        offset = targets[0] - start
        assert after >= offset + GREP_MARGIN_LINES, (
            f"{where}: `grep -A{after} '{pattern}'` stops {after} lines in, but "
            f"`{key}` is {offset} lines below the section header — "
            f"{'exactly the last line printed' if after == offset else 'past the window'}"
            f". Needs at least -A{offset + GREP_MARGIN_LINES}.")
        checked.add(pattern)
    assert checked == set(GREP_MUST_REACH), (
        "a section this test is supposed to check no longer has an action "
        f"grepping for it, so nothing was verified: {set(GREP_MUST_REACH) - checked}")


# ---------------------------------------------------------------------------
# The refusal these instructions collide with is real
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,flag", [("scan", "--now"),
                                       ("maintenance", "--prune")])
def test_the_service_really_refuses_the_flag_the_alert_used_to_name(
        name, flag, capsys):
    """Proof that the two repairs above were necessary, not cosmetic.

    If `parse_service_args` ever went back to dropping what it does not
    recognise, everything in this file would still pass while the real hazard
    — a typo read as "start the daemon" — came back.
    """
    module = importlib.import_module(f"sentinel.services.{name}_service")
    with pytest.raises(SystemExit) as exc:
        module.main([flag])
    assert exc.value.code == 64
    assert flag in capsys.readouterr().err
