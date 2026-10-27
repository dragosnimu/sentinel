"""`/update` PROPUNE planuri; nu are un al doilea drum de aplicare.

## Eșecul pe care îl previne

Aplicarea unui plan are o singură poartă: două atingeri, PIN, o semnătură făcută pe stația
operatorului asupra comenzilor exacte, înregistrată în executor cu un nonce emis de el
(`patch_flow` -> `approval` -> `runner`). O comandă nouă care ar aproba, înregistra sau rula
ceva «pe lângă» ar fi două porți cu aceeași cheie — iar una dintre ele s-ar dezactualiza
primul: prima corecție de securitate care ar atinge-o pe cea veche ar lăsa-o pe a doua
deschisă. Operatorul n-ar afla, fiindcă comanda ar continua să funcționeze.

Codul care construiește planurile (`sentinel/patch/system_update.py`) și textul (`update_view.py`)
nu au voie să atingă executorul; comanda din `bot.py` nu are voie să cheme nimic din
aprobare sau din runner. Singurele comenzi pe care le rulează `system_update` ele însele sunt
interogări de citire (`rpm -q`, `dpkg-query -W`), iar singurele scrieri în bază sunt
`store_plan` și `mark_plan_notified`.

Găsit prin AST, nu prin regex: un apel scris pe mai multe linii sau importat sub alt nume ar
scăpa unui tipar pe text.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSTEM_UPDATE = ROOT / "sentinel" / "patch" / "system_update.py"
UPDATE_VIEW = ROOT / "sentinel" / "telegram" / "update_view.py"
BOT = ROOT / "sentinel" / "telegram" / "bot.py"

#: Module care vorbesc cu executorul sau schimbă gazda.
FORBIDDEN_MODULES = ("sentinel.patch.runner", "sentinel.patch.backup",
                     "sentinel.respond.executor_client", "sentinel.respond", "subprocess")

#: Ce poate lua `system_update` din fiecare modul de lângă el: funcții PURE.
ALLOWED_ATTRS = {
    "approval": {"flatten", "build_request", "ApprovalError", "RUN_BUDGET_S", "MAX_REQUEST_CHARS"},
    "checks": {"_format_evr", "_parse_rpm_evr", "_parse_deb_evr", "_rpm_evr_cmp", "_deb_evr_cmp"},
    "repo": {"store_plan", "mark_plan_notified"},
}
READ_ONLY_PROGRAMS = {"rpm", "dpkg-query"}

#: Numele pe care comanda din bot nu are voie să le atingă.
FORBIDDEN_NAMES = {"run_plan", "approve_plan", "register", "register_plan", "challenge", "runner",
                   "consume", "issue", "ExecutorClient", "revoke_for_plan", "set_plan_status",
                   "on_stage1", "on_stage2", "_approve_and_run", "_ask_for_approval"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _imported(tree: ast.Module) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
            out |= {f"{node.module}.{a.name}" for a in node.names}
    return out


def _attrs_on(tree: ast.Module, base: str) -> set[str]:
    return {n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == base}


def _function(tree: ast.Module, name: str) -> ast.AsyncFunctionDef:
    return next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == name)


def test_the_update_modules_import_nothing_that_talks_to_the_executor():
    """Dacă `system_update` sau `update_view` ar importa runnerul, backup-ul sau clientul
    executorului, ar fi un drum spre root care ocolește `patch_flow`."""
    for path in (SYSTEM_UPDATE, UPDATE_VIEW):
        names = _imported(_tree(path))
        bad = {n for n in names if any(n == m or n.startswith(m + ".") for m in FORBIDDEN_MODULES)}
        assert not bad, f"{path.name} importă {sorted(bad)}"


def _module_uses(tree: ast.Module, base: str) -> tuple[set[str], set[str]]:
    """(nume luate din modulul `base`, atribute folosite pe el) — pe TOATE formele de import.

    `from sentinel.patch import checks` + `checks.evaluate` e forma pe care o folosește codul azi;
    `from sentinel.patch.checks import evaluate` (cu sau fără alias) și
    `from sentinel.patch import checks as ck` + `ck.evaluate` sunt aceleași nume luate pe altă
    ușă. O gardă care vedea doar prima formă lăsa a doua să treacă: `evaluate` rulează comenzi ca
    root, iar `register` înregistrează o aprobare."""
    taken: set[str] = set()
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == f"sentinel.patch.{base}" or (node.level and module == base):
                taken |= {a.name for a in node.names}          # `*` rămâne `*`: nu e în nicio listă
            elif module == "sentinel.patch" or (node.level and module == ""):
                aliases |= {a.asname or a.name for a in node.names if a.name == base}
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == f"sentinel.patch.{base}":
                    aliases.add(a.asname or a.name)
    aliases.add(base)
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and (
        (isinstance(n.value, ast.Name) and n.value.id in aliases)
        or (isinstance(n.value, ast.Attribute) and n.value.attr == base))}
    return taken, attrs


def test_the_update_modules_use_only_the_pure_parts_of_approval_and_checks():
    """`approval` are `challenge` și `register` (care vorbesc cu executorul), `checks` are `evaluate`
    (care rulează comenzi ca root). Planificatorul are nevoie doar de cele pure: dimensiunea
    cererii și comparațiile de versiuni. Garda se uită la ORICE formă de import, nu doar la
    `approval.X`: `from sentinel.patch.checks import evaluate` ar fi trecut."""
    tree = _tree(SYSTEM_UPDATE)
    for base, allowed in ALLOWED_ATTRS.items():
        if base == "repo":
            continue
        taken, used = _module_uses(tree, base)
        assert used, f"nu se mai folosește `{base}` — garda nu mai vede nimic"
        assert used <= allowed, f"system_update.py cheamă {base}.{sorted(used - allowed)}"
        assert taken <= allowed, f"system_update.py importă din {base}: {sorted(taken - allowed)}"


def test_the_import_guard_sees_every_door_into_approval_and_checks():
    """Garda de mai sus e doar atât de bună cât forma de import pe care o recunoaște. Fiecare formă
    prin care `evaluate` sau `register` ar putea intra trebuie să iasă în afara listei permise —
    altfel un import scris altfel ar ocoli poarta cu două atingeri fără ca vreun test să roșească."""
    doors = {
        "from sentinel.patch.checks import evaluate": ("checks", {"evaluate"}, set()),
        "from sentinel.patch.checks import evaluate as run_it": ("checks", {"evaluate"}, set()),
        "from sentinel.patch.approval import register": ("approval", {"register"}, set()),
        "from sentinel.patch.approval import *": ("approval", {"*"}, set()),
        "from sentinel.patch import checks as ck\nck.evaluate()": ("checks", set(), {"evaluate"}),
        "import sentinel.patch.approval as ap\nap.register()": ("approval", set(), {"register"}),
        "import sentinel.patch.checks\nsentinel.patch.checks.evaluate()": ("checks", set(), {"evaluate"}),
        "from sentinel.patch import approval\napproval.challenge()": ("approval", set(), {"challenge"}),
    }
    for source, (base, want_taken, want_used) in doors.items():
        taken, used = _module_uses(ast.parse(source), base)
        assert (taken, used) == (want_taken, want_used), (source, taken, used)
        assert not (taken | used) <= ALLOWED_ATTRS[base], f"{source!r} ar trece garda"
    # Și formele permise rămân permise: garda nu poate fi atât de strictă încât să fie ștearsă.
    taken, used = _module_uses(ast.parse("from sentinel.patch import checks\nchecks._rpm_evr_cmp(1, 2)"),
                               "checks")
    assert (taken | used) <= ALLOWED_ATTRS["checks"] and used == {"_rpm_evr_cmp"}


def test_the_only_commands_system_update_runs_itself_are_read_only_queries():
    """Singurul loc care pornește un proces e `_run`, iar apelanții lui dau doar `rpm`/`dpkg-query`.
    Un `_run(["dnf", ...])` ar fi o aplicare fără nicio semnătură."""
    tree = _tree(SYSTEM_UPDATE)
    spawns = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
              and getattr(n.func, "attr", "") == "create_subprocess_exec"]
    assert len(spawns) == 1, "procese pornite în mai mult de un loc"
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "_run"]
    assert len(calls) >= 3, "garda nu mai vede apelurile lui _run"
    for call in calls:
        argv = call.args[0]
        assert isinstance(argv, ast.List) and argv.elts and isinstance(argv.elts[0], ast.Constant), \
            f"linia {call.lineno}: argv-ul nu e o listă literală cu programul în față"
        assert argv.elts[0].value in READ_ONLY_PROGRAMS, \
            f"linia {call.lineno}: {argv.elts[0].value!r} nu e o interogare de citire"


def test_the_command_in_bot_py_reaches_for_nothing_in_the_approval_or_the_runner():
    """Comanda construiește un plan și îl DĂ lui `send_plan_for_approval`. Aprobarea, PIN-ul,
    semnătura și rularea rămân ale lui `patch_flow`."""
    tree = _tree(BOT)
    for fname in ("cmd_update", "_update_overview"):
        fn = _function(tree, fname)
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
        assert not names & FORBIDDEN_NAMES, f"{fname} atinge {sorted(names & FORBIDDEN_NAMES)}"
    used = _attrs_on(ast.Module(body=[_function(tree, "cmd_update")], type_ignores=[]), "patch_flow")
    assert used == {"send_plan_for_approval"}, used
