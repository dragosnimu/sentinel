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

#: Modulul în care trăiește `system_update`: ancora pentru importurile relative (`from ..db.repo ...`).
THIS_MODULE = "sentinel.patch.system_update"

#: Ce poate lua `system_update` din fiecare modul pe care îl atinge: doar ce e PUR, plus cele
#: două scrieri. Cheia e numele COMPLET al modulului, nu ultima lui componentă: cele trei module
#: stau în două pachete (`sentinel.patch`, `sentinel.db.repo`), iar `repo` nici nu e numele lui —
#: codul îl importă ca `from sentinel.db.repo import patches as repo`.
ALLOWED_ATTRS = {
    "sentinel.patch.approval": {"flatten", "build_request", "ApprovalError", "RUN_BUDGET_S",
                                "MAX_REQUEST_CHARS"},
    "sentinel.patch.checks": {"_format_evr", "_parse_rpm_evr", "_parse_deb_evr", "_rpm_evr_cmp",
                              "_deb_evr_cmp"},
    "sentinel.db.repo.patches": {"store_plan", "mark_plan_notified"},
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


def _absolute(node: ast.ImportFrom, current: str = THIS_MODULE) -> str:
    """Modulul pe care îl numește un `from ... import`, cu forma relativă rezolvată față de
    modulul curent: `from ..db.repo import patches` din `sentinel.patch.system_update` e
    `sentinel.db.repo`."""
    if not node.level:
        return node.module or ""
    base = current.split(".")[:-node.level]
    return ".".join(base + ([node.module] if node.module else []))


def _import_forms(tree: ast.Module, target: str, current: str = THIS_MODULE) -> tuple[set[str], set[str]]:
    """(nume luate DIN `target`, nume locale sub care `target` ÎNSUȘI e legat) — doar ce spun
    importurile, fără numele gol al modulului. Separat de `_module_uses` ca un test să poată
    întreba «văd măcar importul?» fără să-l amestece cu folosirea."""
    parent, _, base = target.rpartition(".")
    taken: set[str] = set()
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = _absolute(node, current)
            if module == target:
                taken |= {a.name for a in node.names}          # `*` rămâne `*`: nu e în nicio listă
            elif module == parent:
                aliases |= {a.asname or a.name for a in node.names if a.name == base}
        elif isinstance(node, ast.Import):
            aliases |= {a.asname or a.name for a in node.names if a.name == target}
    return taken, aliases


def _module_uses(tree: ast.Module, target: str, current: str = THIS_MODULE) -> tuple[set[str], set[str]]:
    """(nume luate din modulul `target`, atribute folosite pe el) — pe TOATE formele de import.

    `target` e numele COMPLET (`sentinel.patch.checks`, `sentinel.db.repo.patches`). Prima versiune
    a ghicit pachetul (`sentinel.patch.<nume>`), iar `repo` nu e în `sentinel.patch`: garda lui a
    fost sărită cu un `continue` în loc să fie modelată, și `repo.set_plan_status` a trecut
    nevăzut. Acum pachetul vine din `target`, iar testul principal cere ca importul să fie
    RECUNOSCUT — un set gol nu mai poate trece drept «nu folosește nimic».

    `from sentinel.patch import checks` + `checks.evaluate` e forma pe care o folosește codul;
    `from sentinel.patch.checks import evaluate` (cu sau fără alias), `from sentinel.patch import
    checks as ck` + `ck.evaluate`, `import sentinel.patch.checks`, formele relative și
    `from sentinel.db import repo` + `repo.patches.X` sunt aceleași nume luate pe altă ușă."""
    base = target.rpartition(".")[2]
    taken, aliases = _import_forms(tree, target, current)
    aliases = aliases | {base}
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and (
        (isinstance(n.value, ast.Name) and n.value.id in aliases)
        or (isinstance(n.value, ast.Attribute) and n.value.attr == base))}
    return taken, used


def _escapes(tree: ast.Module, target: str, current: str = THIS_MODULE) -> set[str]:
    """Numele locale ale modulului `target` folosite ALTFEL decât ca `nume.atribut`: `r = repo`
    urmat de `r.set_plan_status()`, `getattr(repo, ...)`, modulul pasat unei funcții. Garda pe
    atribute nu le vede — după atribuire, `r` nu mai e un alias pe care îl cunoaște."""
    _, aliases = _import_forms(tree, target, current)
    bases = {n.value for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    return {n.id for n in ast.walk(tree)
            if isinstance(n, ast.Name) and n.id in aliases and isinstance(n.ctx, ast.Load)
            and n not in bases}


def test_the_update_modules_use_only_the_pure_parts_of_approval_and_checks():
    """`approval` are `challenge` și `register` (care vorbesc cu executorul), `checks` are `evaluate`
    (care rulează comenzi ca root), iar `repo` (`sentinel.db.repo.patches`) are `set_plan_status`,
    `approve_plan`, `start_execution`. Planificatorul are nevoie doar de cele pure și de cele două
    scrieri: dimensiunea cererii, comparațiile de versiuni, `store_plan`, `mark_plan_notified`.
    Garda se uită la ORICE formă de import, nu doar la `approval.X`.

    Fiecare modul din listă TREBUIE să fie importat într-o formă pe care garda o recunoaște: dacă
    nu, ea n-ar vedea nimic și ar trece pe gol — exact cum a trecut `repo` când a fost sărit."""
    tree = _tree(SYSTEM_UPDATE)
    for target, allowed in ALLOWED_ATTRS.items():
        taken, aliases = _import_forms(tree, target)
        assert taken or aliases, (f"`{target}` nu mai e importat într-o formă pe care garda o "
                                  "recunoaște — nu vede nimic și ar trece pe gol")
        taken, used = _module_uses(tree, target)
        assert used, f"nu se mai folosește `{target}` — garda nu mai vede nimic"
        assert used <= allowed, f"system_update.py cheamă {target}.{sorted(used - allowed)}"
        assert taken <= allowed, f"system_update.py importă din {target}: {sorted(taken - allowed)}"
        assert not _escapes(tree, target), (f"system_update.py pasă modulul `{target}` mai departe "
                                            f"({sorted(_escapes(tree, target))}): atributele nu "
                                            "mai pot fi verificate")


def test_the_guard_recognises_the_import_form_the_code_really_uses_for_repo():
    """Forma reală e `from sentinel.db.repo import patches as repo`. Dacă garda n-o recunoaște,
    `repo.set_plan_status` (aprobarea unui plan fără cele două atingeri) trece prin tot setul de
    teste fără ca vreunul să roșească — s-a întâmplat: suita întreagă a rămas verde."""
    taken, aliases = _import_forms(_tree(SYSTEM_UPDATE), "sentinel.db.repo.patches")
    assert (taken, aliases) == (set(), {"repo"}), (taken, aliases)


def test_the_import_guard_sees_every_door_into_approval_checks_and_repo():
    """Garda de mai sus e doar atât de bună cât forma de import pe care o recunoaște. Fiecare formă
    prin care `evaluate`, `register` sau `set_plan_status` ar putea intra trebuie să iasă în afara
    listei permise — altfel un import scris altfel ar ocoli poarta cu două atingeri fără ca vreun
    test să roșească. `repo` e în lista asta fiindcă a fost sărit o dată: forma lui reală
    (`... import patches as repo`) nu e în `sentinel.patch`, iar ajutorul presupunea că toate sunt."""
    checks, approval = "sentinel.patch.checks", "sentinel.patch.approval"
    patches = "sentinel.db.repo.patches"
    doors = {
        "from sentinel.patch.checks import evaluate": (checks, {"evaluate"}, set()),
        "from sentinel.patch.checks import evaluate as run_it": (checks, {"evaluate"}, set()),
        "from sentinel.patch.approval import register": (approval, {"register"}, set()),
        "from sentinel.patch.approval import *": (approval, {"*"}, set()),
        "from sentinel.patch import checks as ck\nck.evaluate()": (checks, set(), {"evaluate"}),
        "import sentinel.patch.approval as ap\nap.register()": (approval, set(), {"register"}),
        "import sentinel.patch.checks\nsentinel.patch.checks.evaluate()": (checks, set(), {"evaluate"}),
        "from sentinel.patch import approval\napproval.challenge()": (approval, set(), {"challenge"}),
        "from . import checks\nchecks.evaluate()": (checks, set(), {"evaluate"}),
        "from .checks import evaluate": (checks, {"evaluate"}, set()),
        # `repo` = sentinel.db.repo.patches, în TOATE formele care îl pot aduce
        "from sentinel.db.repo import patches as repo\nrepo.set_plan_status()":
            (patches, set(), {"set_plan_status"}),
        "from sentinel.db.repo import patches\npatches.approve_plan()":
            (patches, set(), {"approve_plan"}),
        "from sentinel.db.repo import patches as p\np.start_execution()":
            (patches, set(), {"start_execution"}),
        "from sentinel.db.repo.patches import set_plan_status": (patches, {"set_plan_status"}, set()),
        "from sentinel.db.repo.patches import approve_plan as go": (patches, {"approve_plan"}, set()),
        "from sentinel.db.repo.patches import *": (patches, {"*"}, set()),
        "import sentinel.db.repo.patches as p\np.set_plan_status()": (patches, set(), {"set_plan_status"}),
        "import sentinel.db.repo.patches\nsentinel.db.repo.patches.set_plan_status()":
            (patches, set(), {"set_plan_status"}),
        "from sentinel.db import repo\nrepo.patches.set_plan_status()":
            (patches, set(), {"set_plan_status"}),
        "from ..db.repo import patches as repo\nrepo.set_plan_status()":
            (patches, set(), {"set_plan_status"}),
        "from ..db.repo.patches import set_plan_status": (patches, {"set_plan_status"}, set()),
        "from .. import db\ndb.repo.patches.set_plan_status()": (patches, set(), {"set_plan_status"}),
    }
    for source, (target, want_taken, want_used) in doors.items():
        taken, used = _module_uses(ast.parse(source), target)
        assert (taken, used) == (want_taken, want_used), (source, taken, used)
        assert not (taken | used) <= ALLOWED_ATTRS[target], f"{source!r} ar trece garda"
    # Și formele permise rămân permise: garda nu poate fi atât de strictă încât să fie ștearsă.
    legit = {
        "from sentinel.patch import checks\nchecks._rpm_evr_cmp(1, 2)":
            ("sentinel.patch.checks", {"_rpm_evr_cmp"}),
        "from sentinel.db.repo import patches as repo\nrepo.store_plan()\nrepo.mark_plan_notified()":
            ("sentinel.db.repo.patches", {"store_plan", "mark_plan_notified"}),
    }
    for source, (target, want_used) in legit.items():
        taken, used = _module_uses(ast.parse(source), target)
        assert (taken | used) <= ALLOWED_ATTRS[target] and used == want_used, (source, taken, used)


def test_the_guard_sees_a_module_handed_on_under_another_name():
    """`r = repo` urmat de `r.set_plan_status()` nu folosește niciun atribut pe un alias cunoscut:
    garda pe atribute ar rămâne verde. Se prinde predarea modulului în sine."""
    patches = "sentinel.db.repo.patches"
    head = "from sentinel.db.repo import patches as repo\n"
    for body in ("r = repo\nr.set_plan_status()", "getattr(repo, 'set_plan_status')()",
                 "helper(repo)", "[repo][0].approve_plan()"):
        assert _escapes(ast.parse(head + body), patches) == {"repo"}, body
    assert _escapes(ast.parse(head + "repo.store_plan()\nrepo.mark_plan_notified()"), patches) == set()


#: Tot ce pornește un proces. Forma `shell` e cea prin care o gardă pe argv se ocolește: un singur
#: șir cu `;` în el nu are un «program în față» de verificat.
SPAWN_NAMES = {"create_subprocess_exec", "create_subprocess_shell", "subprocess_exec",
               "subprocess_shell"}
OS_SPAWN_ATTRS = {"system", "popen"}


def _spawns(tree: ast.Module) -> list[ast.Call]:
    """Apelurile care pornesc un proces, sub orice formă: `asyncio.create_subprocess_exec(...)`,
    `create_subprocess_shell(...)` importat gol, `loop.subprocess_shell(...)`, `os.system`,
    `os.popen` — și `import os as o` / `from os import system as sh`."""
    os_names = {"os"}
    bare = set(SPAWN_NAMES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            os_names |= {a.asname for a in node.names if a.name == "os" and a.asname}
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            bare |= {a.asname for a in node.names if a.name in OS_SPAWN_ATTRS and a.asname}
            bare |= {a.name for a in node.names if a.name in OS_SPAWN_ATTRS}
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        on_os = (isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                 and n.func.value.id in os_names and n.func.attr in OS_SPAWN_ATTRS)
        name = getattr(n.func, "attr", None) if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", None)
        if on_os or (name in SPAWN_NAMES) or (isinstance(n.func, ast.Name) and n.func.id in bare):
            out.append(n)
    return out


def test_the_spawn_detector_knows_the_shell_forms_too():
    """Un `_run` care ar porni `asyncio.create_subprocess_shell` sau `os.system` ar fi o aplicare
    fără nicio semnătură, iar numărătoarea de mai jos (doar `create_subprocess_exec`) ar fi
    rămas la unu — verde."""
    for source in ("asyncio.create_subprocess_exec('rpm')", "asyncio.create_subprocess_shell('rpm; x')",
                   "create_subprocess_shell('x')", "loop.subprocess_shell(f, 'x')",
                   "loop.subprocess_exec(f, 'x')", "os.system('x')", "os.popen('x')",
                   "import os as o\no.system('x')", "from os import system\nsystem('x')",
                   "from os import popen as sh\nsh('x')"):
        assert len(_spawns(ast.parse(source))) == 1, source
    assert not _spawns(ast.parse("system('x')\nself.popen('x')\nos.path.join('a')"))


def test_the_only_commands_system_update_runs_itself_are_read_only_queries():
    """Singurul loc care pornește un proces e `_run`, iar apelanții lui dau doar `rpm`/`dpkg-query`.
    Un `_run(["dnf", ...])` ar fi o aplicare fără nicio semnătură."""
    tree = _tree(SYSTEM_UPDATE)
    spawns = _spawns(tree)
    assert len(spawns) == 1, "procese pornite în mai mult de un loc"
    assert getattr(spawns[0].func, "attr", "") == "create_subprocess_exec", \
        "singurul proces pornit trebuie să fie forma cu argv, nu cea cu shell"
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
