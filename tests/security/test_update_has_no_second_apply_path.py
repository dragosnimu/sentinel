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

## Ce se verifică, și de ce în patru locuri

Promisiunea de mai sus are patru uși, iar garda o păzea doar pe jumătate de ușă: lista de
atribute permise se uita la ce se ia din TREI module, dar nimic nu limita CARE module se
importă, ce se cheamă pe obiectul `Database`, ce text SQL i se dă, sau ce procese se pot
porni în afară de `system`/`popen`. O singură mutație (`approvals.issue`, un
`db.execute("INSERT ...")` și un `os.posix_spawn`) a lăsat suita verde. Acum:

  1. fiecare modul `sentinel.*` importat e pe o listă numită (`ALLOWED_SENTINEL_MODULES`), iar
     driverele de bază (`asyncpg`, `psycopg*`) nu se importă deloc: modulul primește un `Database`,
     nu are niciun motiv să-și deschidă propria conexiune;
  2. pe obiectul `Database` se cheamă doar `fetch`/`fetchrow`, iar obiectul nu iese din
     funcțiile care îl primesc ca `Database`;
  3. textul fiecărei interogări e un literal care începe cu `SELECT`/`WITH`, nu conține niciun verb
     de scriere și nu cheamă o funcție a schemei — iar ce nu se poate citi pică, nu trece (inclusiv
     comentariile, `E'..'`, `$$..$$` și identificatorii între ghilimele: oricare dintre ele
     schimbă ce e «literal» și poate ascunde un verb); singura interpolare permisă trebuie să fie
     funcția reală, importată, iar textul ei real e cel scanat;
  4. orice formă de a porni un proces din `os` (`posix_spawn`, `spawn*`, `exec*`, `fork`), inclusiv
     prin `os`-ul unui modul `sentinel.*` (`os_packages.os.system`), și orice argv `rpm`/`dpkg-query`
     care nu e o interogare (`rpm --eval "%(...)"` rulează un shell).

Garda mărginește FELUL instrucțiunii, nu efectul ei: un `SELECT` care cheamă `pg_terminate_backend`
sau `nextval` nu se vede de aici (funcțiile schemei `sentinel_*` se văd, vezi poarta 3). Rolul bazei
de date nu e o limită pentru tabelele acestui modul (`sentinel` are `INSERT`/`UPDATE`/`DELETE` pe
`patch_plans`), deci poarta 3 e singura.

Uși CUNOSCUTE și lăsate deschise, ca un cititor să nu creadă că sunt păzite: `importlib`/`__import__`,
`pty`, `ctypes`, `multiprocessing`, `socket`, `run_in_executor(None, os.system, ...)`,
`asyncio.to_thread(os.system, ...)`, `getattr(os, "posix_spawn")(...)`, `globals()[...] = ...`.
Niciuna nu e un import sau un apel pe care `_spawns` să-l poată citi; sunt ocoliri deliberate, nu
greșeli de scriere, iar un revizuitor le vede în diff.
"""
from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

from sentinel.db.repo.findings import pending_reboot_sql

ROOT = Path(__file__).resolve().parents[2]
SYSTEM_UPDATE = ROOT / "sentinel" / "patch" / "system_update.py"
UPDATE_VIEW = ROOT / "sentinel" / "telegram" / "update_view.py"
UPDATE_VIEW_MODULE = "sentinel.telegram.update_view"
BOT = ROOT / "sentinel" / "telegram" / "bot.py"

#: Module care vorbesc cu executorul sau schimbă gazda — plus driverele de bază: `system_update`
#: primește un `Database`, deci o conexiune proprie (`asyncpg.connect`, `psycopg.connect`) ocolește
#: TOATĂ poarta 2 (nicio legare, niciun apel pe `Database`). S-a dovedit: `c = await
#: asyncpg.connect(dsn); await c.fetchmany("INSERT ...")` a trecut garda și suita întreagă, fiindcă
#: `fetchmany` lipsea și din `DB_METHODS`. Nu există un motiv cinstit pentru ele în aceste module.
FORBIDDEN_MODULES = ("sentinel.patch.runner", "sentinel.patch.backup",
                     "sentinel.respond.executor_client", "sentinel.respond", "subprocess",
                     "asyncpg", "psycopg", "psycopg2", "psycopg_pool")

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

#: TOATE modulele `sentinel.*` pe care `system_update` are voie să le importe, numite una câte una.
#: Lista de mai sus (`ALLOWED_ATTRS`) spune ce se poate lua din trei dintre ele; asta spune care
#: există, în general. Un modul nou (`sentinel.db.repo.approvals` are `issue`/`consume`/
#: `revoke_for_plan`) e un import pe care un om trebuie să-l vadă și să-l aprobe PE NUME, aici —
#: nu un import care trece fiindcă nu e în `FORBIDDEN_MODULES`. O intrare care nu mai e importată
#: trebuie ștearsă și ea: altfel ar aproba dinainte o reintroducere.
ALLOWED_SENTINEL_MODULES = frozenset({
    "sentinel.constants", "sentinel.db.engine",
    "sentinel.db.repo.patches", "sentinel.db.repo.findings",
    "sentinel.logging_setup",
    "sentinel.patch.validator", "sentinel.patch.checks", "sentinel.patch.planner",
    "sentinel.patch.approval",
    "sentinel.scan.os_packages", "sentinel.scan.subject",
})

#: Numele pe care comanda din bot nu are voie să le atingă.
FORBIDDEN_NAMES = {"run_plan", "approve_plan", "register", "register_plan", "challenge", "runner",
                   "consume", "issue", "ExecutorClient", "revoke_for_plan", "set_plan_status",
                   "on_stage1", "on_stage2", "_approve_and_run", "_ask_for_approval"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


UNRESOLVABLE = "<nerezolvabil>"


def _imported(tree: ast.Module, current: str = THIS_MODULE) -> set[str]:
    """Numele COMPLETE ale modulelor importate, cu importurile relative rezolvate față de `current`.

    Prima versiune citea `node.module` așa cum e scris: `from ..patch import runner` era înregistrat
    ca `patch` și `patch.runner`, care nu potrivesc niciodată `FORBIDDEN_MODULES` (cheile lor încep
    cu `sentinel.`), iar `from . import runner` (fără `module`) nu era înregistrat deloc. Un import
    relativ care iese din pachetul rădăcină nu se poate rezolva: apare ca `UNRESOLVABLE...` și pică
    în test — «nu știu» nu devine «e bine»."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level >= len(current.split(".")):
                out.add(f"{UNRESOLVABLE}{'.' * node.level}{node.module or ''}")
                continue
            module = _absolute(node, current)
            out.add(module)
            out |= {f"{module}.{a.name}" for a in node.names}
    return out


def _banned_imports(tree: ast.Module, current: str) -> set[str]:
    return {n for n in _imported(tree, current) if n.startswith(UNRESOLVABLE)
            or any(n == m or n.startswith(m + ".") for m in FORBIDDEN_MODULES)}


def _attrs_on(tree: ast.Module, base: str) -> set[str]:
    return {n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == base}


def _function(tree: ast.Module, name: str) -> ast.AsyncFunctionDef:
    return next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == name)


def test_the_update_modules_import_nothing_that_talks_to_the_executor():
    """Dacă `system_update` sau `update_view` ar importa runnerul, backup-ul sau clientul
    executorului, ar fi un drum spre root care ocolește `patch_flow`."""
    for path, current in ((SYSTEM_UPDATE, THIS_MODULE), (UPDATE_VIEW, UPDATE_VIEW_MODULE)):
        bad = _banned_imports(_tree(path), current)
        assert not bad, f"{path.name} importă {sorted(bad)}"


def test_the_import_ban_sees_relative_and_database_driver_imports():
    """`from ..patch import runner` în `update_view` (sau `from . import runner` în `system_update`)
    ar da textului de pe ecran drumul spre executor, iar `import asyncpg` ar da modulului propria
    conexiune la bază, fără `Database`, fără poarta SQL. Numele relative, nerezolvate, nu potriveau
    nimic din `FORBIDDEN_MODULES`, iar driverele nu erau pe listă: suita rămânea verde. Controlul:
    importurile pe care modulele le fac azi trec."""
    for source, current in (
            ("from ..patch import runner", UPDATE_VIEW_MODULE),
            ("from ..patch.runner import run_plan", UPDATE_VIEW_MODULE),
            ("from . import runner", THIS_MODULE),
            ("from .runner import run_plan", THIS_MODULE),
            ("from .. import respond", THIS_MODULE),
            ("from ..respond.executor_client import ExecutorClient", THIS_MODULE),
            ("from .... import x", THIS_MODULE),
            ("import asyncpg", THIS_MODULE),
            ("import asyncpg as pg", THIS_MODULE),
            ("from asyncpg import connect", THIS_MODULE),
            ("def f():\n    import psycopg", THIS_MODULE),
            ("import psycopg2.extras", THIS_MODULE),
            ("from psycopg import AsyncConnection", THIS_MODULE),
            ("from psycopg_pool import AsyncConnectionPool", THIS_MODULE),
            ("import subprocess", THIS_MODULE)):
        assert _banned_imports(ast.parse(source), current), (source, current)
    for source, current in (
            ("from sentinel.patch import system_update as su", UPDATE_VIEW_MODULE),
            ("from . import checks\nfrom .checks import evaluate", THIS_MODULE),
            ("from ..db.repo import patches as repo", THIS_MODULE),
            ("import asyncio\nimport os\nimport re\nfrom typing import Any", THIS_MODULE),
            ("import asyncpg_helpers_are_not_asyncpg", THIS_MODULE)):
        assert not _banned_imports(ast.parse(source), current), (source, current)


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


# ---------------------------------------------------------------------------
# 1. Ce module `sentinel.*` se importă
# ---------------------------------------------------------------------------
def _is_ours(name: str) -> bool:
    return name == "sentinel" or name.startswith("sentinel.")


def _unlisted_sentinel_imports(tree: ast.Module, allowed: frozenset[str] = ALLOWED_SENTINEL_MODULES,
                               current: str = THIS_MODULE) -> list[tuple[int, str]]:
    """(linie, nume complet) pentru fiecare import `sentinel.*` care nu e în `allowed`, pe TOATE
    formele: `import a.b`, `import a.b as x`, `from a import b`, `from a.b import c`, relativ
    (`from ..db.repo import approvals`), la nivel de modul sau în funcție.

    De ce nu `_import_forms`: aceea răspunde la «cum e importat modulul X?» pentru un X cunoscut;
    aici întrebarea e «ce ALTCEVA e importat?», deci trebuie parcurse toate importurile. Ce se
    refolosește e `_absolute` (rezolvarea formelor relative) — fără ea `from . import runner`
    ar scăpa, cum scapă și de `FORBIDDEN_MODULES`, care citește numele nerezolvate.

    `from P import n` poate lua un submodul (`from sentinel.patch import checks`) sau un nume
    (`from sentinel.constants import X`); de aceea trece dacă fie `P`, fie `P.n` e pe listă. Un
    `from sentinel.db.repo import approvals` nu are niciuna dintre ele: pică. Un import relativ care
    iese din pachetul rădăcină nu se poate rezolva și pică și el: «nu știu» nu devine «e bine»."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(node.lineno, a.name) for a in node.names if _is_ours(a.name) and a.name not in allowed]
        elif isinstance(node, ast.ImportFrom):
            module = _absolute(node, current)
            if node.level >= len(current.split(".")):         # iese din pachetul rădăcină: nerezolvabil
                out.append((node.lineno, "." * node.level + (node.module or "")))
            elif _is_ours(module):
                out += [(node.lineno, f"{module}.{a.name}") for a in node.names
                        if module not in allowed and f"{module}.{a.name}" not in allowed]
    return sorted(out)


def test_system_update_imports_only_the_sentinel_modules_on_the_list():
    """Un `from sentinel.db.repo import approvals` (cu `approvals.issue`) sau orice alt modul
    `sentinel.*` nou ar da lui `system_update` o ușă pe care nicio listă de atribute n-o vede:
    `ALLOWED_ATTRS` știe doar trei module. Pică la importul în sine, cu numele modulului."""
    tree = _tree(SYSTEM_UPDATE)
    bad = _unlisted_sentinel_imports(tree)
    assert not bad, (
        f"system_update.py importă module `sentinel.*` care nu sunt aprobate pe nume: "
        f"{[f'linia {n}: {name}' for n, name in bad]}. Un modul nou e o ușă nouă: dacă îl vrei cu "
        "adevărat, adaugă-l în ALLOWED_SENTINEL_MODULES ÎN ACEEAȘI schimbare, cu motivul, ca "
        "revizuitorul să-l vadă; dacă e doar o scurtătură, folosește ce exportă deja un modul de "
        "pe listă. Nu lărgi lista ca să treacă testul.")
    # Garda trece pe gol dacă nu vede nimic; și o intrare rămasă în urmă aprobă dinainte o revenire.
    for module in sorted(ALLOWED_SENTINEL_MODULES):
        taken, aliases = _import_forms(tree, module)
        assert taken or aliases, (f"`{module}` e în ALLOWED_SENTINEL_MODULES dar nu mai e importat "
                                  "(sau e importat într-o formă pe care garda nu o recunoaște): "
                                  "șterge intrarea, nu o lăsa să aprobe o reintroducere")
    assert set(ALLOWED_ATTRS) <= ALLOWED_SENTINEL_MODULES, \
        "un modul cu atribute permise trebuie să fie și pe lista modulelor"


def test_the_module_allow_list_sees_every_door_and_still_admits_the_modules_on_it():
    """Dacă garda ar recunoaște doar `from X import Y`, un `import sentinel.db.repo.approvals as a`
    sau un `from ..db.repo import approvals` ar aduce `approvals.issue` fără ca vreun test să
    roșească; dacă ar respinge și modulele de pe listă, ar fi ștearsă a doua zi."""
    bad = {
        "from sentinel.db.repo import approvals": ["sentinel.db.repo.approvals"],
        "from sentinel.db.repo import approvals as a": ["sentinel.db.repo.approvals"],
        "from sentinel.db.repo.approvals import issue": ["sentinel.db.repo.approvals.issue"],
        "import sentinel.db.repo.approvals": ["sentinel.db.repo.approvals"],
        "import sentinel.db.repo.approvals as ap": ["sentinel.db.repo.approvals"],
        "from ..db.repo import approvals": ["sentinel.db.repo.approvals"],
        "from ..db.repo.approvals import issue": ["sentinel.db.repo.approvals.issue"],
        "from . import runner": ["sentinel.patch.runner"],
        "from .runner import run_plan": ["sentinel.patch.runner.run_plan"],
        "from sentinel.patch import checks, runner": ["sentinel.patch.runner"],
        "from sentinel.respond.executor_client import ExecutorClient":
            ["sentinel.respond.executor_client.ExecutorClient"],
        "from sentinel import respond": ["sentinel.respond"],
        "import sentinel": ["sentinel"],
        "from sentinel.db.repo import *": ["sentinel.db.repo.*"],
        "def f():\n    from sentinel.db.repo import approvals": ["sentinel.db.repo.approvals"],
        "from ... import x": ["..."],
    }
    for source, want in bad.items():
        got = [name for _, name in _unlisted_sentinel_imports(ast.parse(source))]
        assert got == want, (source, got)
    for source in ("from sentinel.constants import REBOOT_REQUIRED_PACKAGES",
                   "from sentinel.db.engine import Database",
                   "from sentinel.db.repo import patches as repo",
                   "from sentinel.db.repo.findings import pending_reboot_sql",
                   "from sentinel.logging_setup import get_logger",
                   "from sentinel.patch.validator import plan_hash, validate_plan",
                   "from sentinel.patch import checks",
                   "from sentinel.patch import checks as ck, planner",
                   "from sentinel.patch import approval",
                   "from sentinel.scan import os_packages, subject",
                   "import sentinel.patch.checks",
                   "import sentinel.patch.checks as ck",
                   "from . import checks",
                   "from .checks import evaluate",
                   "from ..db.repo import patches as repo",
                   "from ..db.repo.patches import store_plan",
                   "import os\nimport re\nimport json\nfrom typing import Any"):
        assert not _unlisted_sentinel_imports(ast.parse(source)), source


# ---------------------------------------------------------------------------
# 2 + 3. Ce se face cu obiectul `Database`, și ce text SQL i se dă
# ---------------------------------------------------------------------------
#: Singurele metode pe care `system_update` le cheamă pe `Database`: ambele citesc.
DB_READ_ATTRS = frozenset({"fetch", "fetchrow"})

#: Metodele obiectului `Database` și ale conexiunii de sub el. Un apel cu unul dintre ele pe un
#: obiect care NU e legat prin adnotare înseamnă că legarea a pierdut un nume (`conn.execute`
#: într-o funcție al cărei parametru n-are `: Database`). Lista nu se mai ține «din memorie»:
#: `test_db_methods_names_the_whole_query_surface_of_database_and_asyncpg` o compară cu suprafața
#: reală (`Database`, `asyncpg.Connection`, `asyncpg.Pool`), fiindcă o omisiune de un cuvânt
#: (`fetchmany`) a fost cât a trebuit ca o scriere să treacă nevăzută.
DB_METHODS = frozenset({"fetch", "fetchrow", "fetchval", "fetchmany", "execute", "executemany",
                        "transaction", "acquire", "prepare", "cursor", "notify", "listen",
                        "copy_from_query", "copy_from_table", "copy_records_to_table",
                        "copy_to_table"})

SQL_READ_KEYWORDS = frozenset({"SELECT", "WITH"})

#: Singura interpolare permisă într-un f-string de SQL: expresia CONSTANTĂ a lui
#: `findings.pending_reboot_sql` (vezi comentariul de la `load_candidates`). Orice altceva
#: interpolat — un nume de coloană, un verb — face textul necitibil pentru gardă.
#:
#: Cheia e numele din cod; valoarea e (modulul de unde TREBUIE importat, funcția REALĂ). Funcția
#: reală se cheamă la citirea textului, deci poarta scanează ce ar produce ea cu adevărat, nu un
#: surogat. Iar numele trebuie legat în `system_update` DOAR de acel import (`_rebindings`): un
#: `def pending_reboot_sql(alias): return "... INSERT ..."` lăsa importul intact și f-string-ul
#: citit ca un loc gol.
SQL_INTERPOLATIONS = {"pending_reboot_sql": ("sentinel.db.repo.findings", pending_reboot_sql)}

#: Verbe care schimbă baza sau schema. `WITH x AS (INSERT ... RETURNING ...) SELECT ...` începe cu
#: un cuvânt de citire și scrie; `SELECT ... INTO t` creează o tabelă; `FOR UPDATE` ia lacăte. Se
#: caută în text DUPĂ ce literalele între apostrofuri sunt scoase (`status = 'update'` e o valoare).
_SQL_WRITE_WORD = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|ALTER|DROP|CREATE|GRANT|REVOKE|COPY|INTO)\b", re.IGNORECASE)
_SQL_LITERAL = re.compile(r"'(?:[^']|'')*'")
_SQL_HEAD = re.compile(r"\s*([A-Za-z]+)\b")

#: Tot ce schimbă ce înseamnă «literal» pentru `_SQL_LITERAL`, și deci poate ascunde un verb de
#: scriere: comentarii (`-- it's` și `/* ' */` deschid un «literal» fals care înghite verbul),
#: `E'..\''` și `\` (cu `standard_conforming_strings` oprit un `\'` nu închide literalul), dolari
#: (`$$..$$`, `$tag$..$tag$`) și identificatori între ghilimele (`"a'b"`). A scoate întâi
#: comentariile ar fi o a doua gramatică SQL de întreținut, cu aceleași goluri; nicio interogare de
#: azi nu are vreuna dintre ele, deci ce nu se poate modela pică («nu știu» ≠ «e bine»). Se caută în
#: textul ÎNTREG, înainte să se scoată literalele: o valoare `'--'` pică și ea, deliberat.
#: `$1`, `$2::text[]` nu potrivesc (un marcator de parametru nu are `$` după cifre).
_SQL_UNMODELLED = re.compile(r"--|/\*|\\|\"|\$(?:[^\W\d]\w*)?\$|(?<![\w$])[eE]'")

#: Funcțiile definite de schemă (`sentinel_emergency_retention`, `sentinel_drop_old_partitions`...)
#: sunt plpgsql cu efecte: `SELECT sentinel_emergency_retention()` începe cu SELECT și nu are niciun
#: verb de scriere în text, dar șterge partiții. Prefixul e fixat de un test pe migrări
#: (`test_every_callable_schema_function_is_named_by_the_function_gate`).
_SQL_SCHEMA_FUNCTION = re.compile(r"\bsentinel_\w+\s*\(", re.IGNORECASE)


def _functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    a = fn.args
    return [p for p in (*a.posonlyargs, *a.args, a.vararg, *a.kwonlyargs, a.kwarg) if p is not None]


def _is_database_annotation(annotation: ast.expr | None) -> bool:
    """`Database`, `engine.Database`, `Database | None`, `"Database"` — orice adnotare care îl numește."""
    if annotation is None:
        return False
    for n in ast.walk(annotation):
        if (isinstance(n, ast.Name) and n.id == "Database") or \
                (isinstance(n, ast.Attribute) and n.attr == "Database") or \
                (isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and re.search(r"\bDatabase\b", n.value)):
            return True
    return False


def _sql_text(node: ast.expr | None) -> str | None:
    """Textul literal al unei interogări, sau `None` dacă nu poate fi citit întreg: un literal, o
    concatenare implicită (în AST e tot un literal), `"a" + "b"`, sau un f-string ale cărui singure
    interpolări sunt cele din `SQL_INTERPOLATIONS`, cu argumente constante: funcția REALĂ e chemată
    și textul ei intră în interogare, ca să fie scanat ce ar ajunge cu adevărat la bază. Dacă ridică
    sau nu dă un șir, textul e necitibil."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _sql_text(node.left), _sql_text(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif (isinstance(v, ast.FormattedValue) and v.conversion == -1 and v.format_spec is None
                  and isinstance(v.value, ast.Call) and isinstance(v.value.func, ast.Name)
                  and v.value.func.id in SQL_INTERPOLATIONS and not v.value.keywords
                  and all(isinstance(a, ast.Constant) for a in v.value.args)):
                try:
                    produced = SQL_INTERPOLATIONS[v.value.func.id][1](*[a.value for a in v.value.args])
                except Exception:                              # orice eșec al funcției = text necitibil
                    return None
                if not isinstance(produced, str):
                    return None
                parts.append(produced)
            else:
                return None
        return "".join(parts)
    return None


def _sql_problem(text: str) -> tuple[str, str] | None:
    """(fel, detaliu) dacă `text` nu e o citire; `None` dacă e. Primul cuvânt trebuie să fie
    `SELECT`/`WITH` (un comentariu sau o paranteză în față îl ascund, deci pică: un om decide);
    nimic din `_SQL_UNMODELLED` nu are voie să apară (înainte să se scoată literalele: altfel un
    apostrof dintr-un comentariu ar înghiți verbul de scriere); iar în rest nu apare niciun verb de
    scriere și nicio funcție a schemei."""
    shown = " ".join(text.split())[:70]
    head = _SQL_HEAD.match(text)
    if head is None or head.group(1).upper() not in SQL_READ_KEYWORDS:
        return "sql-kind", shown
    odd = _SQL_UNMODELLED.search(text)
    if odd:
        return "sql-unreadable", f"{odd.group(0)!r} în: {shown}"
    plain = _SQL_LITERAL.sub("''", text)
    hit = _SQL_WRITE_WORD.search(plain)
    if hit:
        return "sql-write", f"{hit.group(1).upper()} în: {shown}"
    call = _SQL_SCHEMA_FUNCTION.search(plain)
    if call:
        return "sql-function", f"{call.group(0)} în: {shown}"
    return None


def _param_receiving(fn: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call,
                     arg: ast.expr) -> ast.arg | None:
    """Parametrul lui `fn` care primește `arg` în `call`, sau `None` dacă nu se poate stabili
    (`*args`, `**kw`, mai multe argumente decât parametri)."""
    a = fn.args
    positional = [*a.posonlyargs, *a.args]
    for i, given in enumerate(call.args):
        if given is arg:
            return positional[i] if i < len(positional) else None
    for kw in call.keywords:
        if kw.value is arg and kw.arg is not None:
            return next((p for p in (*a.args, *a.kwonlyargs) if p.arg == kw.arg), None)
    return None


def _database_scan(tree: ast.Module, current: str = THIS_MODULE
                   ) -> tuple[set[str], int, list[tuple[str, int, str]]]:
    """(numele legate la `Database`, câte citiri s-au văzut, constatări `(fel, linie, detaliu)`).

    ## Cum se leagă obiectul, și de ce așa

    LEGAREA = adnotarea. Orice parametru al oricărei funcții adnotat `Database` poartă obiectul,
    oricum s-ar numi. Alternativele, respinse:

      * după numele `db`: o redenumire (`conn`, `pool`, `database`) ar orbi garda fără să roșească
        nimic, iar `db` poate fi alt lucru în altă funcție;
      * prin inferență de tip / flux de date: AST-ul n-are tipuri, iar o analiză de flux e încă un
        program de întreținut, cu propriile goluri.

    Adnotarea e faptul pe care modulul îl declară singur («aici sosește un `Database`») și
    supraviețuiește redenumirii. Ce o completează, ca un nume pierdut să nu scape:

      * un parametru numit `db` FĂRĂ adnotare pică (`unbound`): legarea nu l-ar vedea;
      * un apel de metodă de bază de date (`DB_METHODS`) pe un obiect nelegat pică
        (`unbound-call`): prinde `conn.execute(...)` într-o funcție cu parametrul neadnotat;
      * un nume legat poate fi doar `nume.fetch(...)` / `nume.fetchrow(...)` chemate pe loc, sau
        argument către (a) o funcție a modulului al cărei parametru primitor e și el adnotat, ori
        (b) cele două scrieri permise ale lui `patches`. Orice altceva — `x = db`, `return db`,
        `approvals.issue(db, ...)`, `f = db.fetch`, `helper(db)` către un modul străin — e `escape`;
      * `Database` în afara unei adnotări (construit, pasat) pică (`construct`): n-ar fi legat.

    Toate cad ÎNCHIS: ce garda nu poate dovedi că e o citire e o constatare, nu o trecere."""
    out: list[tuple[str, int, str]] = []
    by_name: dict[str, list] = {}
    bound: set[str] = set()
    for fn in _functions(tree):
        by_name.setdefault(fn.name, []).append(fn)
        for p in _params(fn):
            if _is_database_annotation(p.annotation):
                bound.add(p.arg)
            elif p.arg == "db":
                out.append(("unbound", p.lineno, f"{fn.name}({p.arg})"))

    annotation_nodes: set[int] = set()
    for n in ast.walk(tree):
        notes = {ast.arg: lambda x: x.annotation, ast.AnnAssign: lambda x: x.annotation,
                 ast.FunctionDef: lambda x: x.returns, ast.AsyncFunctionDef: lambda x: x.returns}
        for kind, pick in notes.items():
            if isinstance(n, kind) and pick(n) is not None:
                annotation_nodes |= {id(x) for x in ast.walk(pick(n))}
    for n in ast.walk(tree):
        if ((isinstance(n, ast.Name) and n.id == "Database")
                or (isinstance(n, ast.Attribute) and n.attr == "Database")) and id(n) not in annotation_nodes:
            out.append(("construct", n.lineno, "Database"))

    parent = {child: p for p in ast.walk(tree) for child in ast.iter_child_nodes(p)}
    patches = "sentinel.db.repo.patches"
    _, patch_aliases = _import_forms(tree, patches, current)
    reads: list[ast.Call] = []
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in DB_METHODS
                and not (isinstance(n.func.value, ast.Name) and n.func.value.id in bound)):
            out.append(("unbound-call", n.lineno, n.func.attr))
        if not (isinstance(n, ast.Name) and n.id in bound and isinstance(n.ctx, ast.Load)):
            continue                      # nu e o folosire a obiectului (parametrul însuși, alt nume)
        up = parent[n]
        call = up if isinstance(up, ast.Call) else (parent.get(up) if isinstance(up, ast.keyword) else None)
        if isinstance(up, ast.Attribute) and up.value is n:
            outer = parent.get(up)
            if up.attr not in DB_READ_ATTRS:
                out.append(("attr", n.lineno, f"{n.id}.{up.attr}"))
            elif not (isinstance(outer, ast.Call) and outer.func is up):
                out.append(("detached", n.lineno, f"{n.id}.{up.attr}"))
            else:
                reads.append(outer)
        elif isinstance(call, ast.Call) and call.func is not n:
            func = call.func
            if isinstance(func, ast.Name) and func.id in by_name:
                ok = all(_is_database_annotation(getattr(_param_receiving(fn, call, n), "annotation", None))
                         for fn in by_name[func.id])
            else:
                ok = (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                      and func.value.id in patch_aliases and func.attr in ALLOWED_ATTRS[patches])
            if not ok:
                out.append(("escape", n.lineno, f"{n.id} dat lui {ast.unparse(func)}(...)"))
        else:
            out.append(("escape", n.lineno, ast.unparse(up)[:70]))

    for call in reads:
        arg = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "sql"), None)
        text = None if arg is None or isinstance(arg, ast.Starred) else _sql_text(arg)
        problem = ("sql-unreadable", ast.unparse(arg)[:70] if arg is not None else "(fără interogare)") \
            if text is None else _sql_problem(text)
        if problem:
            out.append((problem[0], call.lineno, problem[1]))
    return bound, len(reads), sorted(out, key=lambda f: (f[1], f[0]))


#: Ce să facă cel care dă de fiecare fel de constatare — scris pentru cine e în mijlocul unei
#: schimbări și caută cel mai scurt drum spre verde.
_DB_ADVICE = {
    "attr": "`system_update` citește din bază; doar `fetch`/`fetchrow`. O scriere nu are ce căuta "
            "aici: se face în `repo.store_plan`/`mark_plan_notified` sau în afara modulului.",
    "detached": "metoda trebuie chemată pe loc, `db.fetch(\"SELECT ...\")`: dacă o ții într-o variabilă, "
                "garda nu mai poate citi interogarea.",
    "sql-kind": "interogarea trebuie să înceapă cu SELECT sau WITH (fără comentariu sau paranteză în "
                "față). Altceva e o scriere și nu are ce căuta pe `fetch`.",
    "sql-write": "un verb de scriere într-o interogare de citire (CTE care scrie, `SELECT ... INTO`, "
                 "`FOR UPDATE`). Dacă e doar o valoare, pune-o ca parametru ($1), nu în text.",
    "sql-unreadable": "garda nu poate citi interogarea (variabilă, concatenare cu ceva necunoscut, "
                      "interpolare, sau un comentariu `--`/`/* */`, `E'..'`, `\\`, `$$`, ghilimele "
                      "duble: ele schimbă ce e literal și pot ascunde un verb). Scrie-o ca literal "
                      "simplu; dacă chiar trebuie construită, un om hotărăște și extinde garda, nu o "
                      "ocolește.",
    "sql-function": "interogarea cheamă o funcție a schemei (`sentinel_*`): sunt plpgsql cu efecte "
                    "(șterg partiții, rulează retenția). O citire nu are de ce să le cheme.",
    "escape": "obiectul `Database` iese din locurile pe care garda le poate urmări. Dă-l doar unei "
              "funcții a modulului al cărei parametru e adnotat `: Database`, sau lui "
              "`repo.store_plan`/`repo.mark_plan_notified`.",
    "unbound": "parametrul `db` nu e adnotat `: Database`; garda leagă obiectul după adnotare, nu "
               "după nume — adnoteaz-o.",
    "unbound-call": "metodă de bază de date chemată pe un obiect nelegat: adnotează parametrul "
                    "`: Database` ca garda să-l vadă, sau nu chema metoda.",
    "construct": "`Database` apare în afara unei adnotări (construit sau pasat): un obiect nou n-ar fi "
                 "legat. `system_update` primește obiectul, nu îl creează.",
}


def test_system_update_reads_the_database_and_only_reads_it():
    """Promisiunea din docstring: singurele scrieri în bază sunt `store_plan` și `mark_plan_notified`.
    Un `db.execute("INSERT ...")`, un `db.fetch("INSERT ... RETURNING id")` sau un `db` pasat lui
    `approvals.issue` ar fi un drum de scriere pe care operatorul nu l-ar vedea — comanda ar continua
    să meargă. Garda cere ca obiectul `Database` să facă doar `fetch`/`fetchrow`, iar textul
    fiecărei interogări să fie o citire pe care o poate citi."""
    tree = _tree(SYSTEM_UPDATE)
    bound, n_reads, findings = _database_scan(tree)
    # Cele două aserțiuni de mai jos NU sunt independente de `_database_scan`: nu pot fi stricate de
    # o schimbare în `system_update`, ci de una în codul de legare al gărzii însăși. Rostul lor e
    # tocmai ăsta — o legare stricată (care nu mai vede nimic) ar lăsa `findings` gol, adică verde.
    assert bound, ("`_database_scan` nu a legat niciun nume la `Database`: fie `system_update` nu mai "
                   "primește un `Database` adnotat, fie legarea gărzii s-a stricat — în ambele cazuri "
                   "garda nu vede nimic și `findings` gol ar fi o trecere pe gol")
    raw = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
           and n.func.attr in DB_READ_ATTRS]
    assert n_reads and n_reads == len(raw), (
        f"garda a văzut {n_reads} citiri din {len(raw)} apeluri `.fetch`/`.fetchrow` numărate separat: "
        "fie codul de legare al gărzii a pierdut un nume (un apel pe care nu-l mai verifică nimeni), fie "
        "numărătoarea de aici s-a desprins de ea")
    assert not findings, "system_update.py nu mai e doar citire din bază:\n" + "\n".join(
        f"  linia {line}: {kind}: {detail}\n      -> {_DB_ADVICE[kind]}" for kind, line, detail in findings)


def _in_fn(body: str, sig: str = "db: Database", before: str = "") -> str:
    head = ("from sentinel.db.engine import Database\nfrom sentinel.db.repo import patches as repo\n"
            "from sentinel.db.repo.findings import pending_reboot_sql\n" + before)
    return head + f"async def f({sig}):\n" + "".join(f"    {ln}\n" for ln in body.split("\n"))


def test_the_database_guard_fires_on_each_way_to_write_or_to_hide_a_query():
    """Fiecare mod prin care `system_update` ar scrie în bază, sau ar ascunde interogarea de gardă,
    trebuie să dea exact felul de constatare așteptat. Cazul `db.fetch("INSERT ...")` e cel pe care
    verificarea pe atribute NU îl poate prinde (`fetch` e permis): îl prinde doar textul SQL."""
    helper = "async def helper(conn: Database, n=0):\n    return await conn.fetch('SELECT 1')\n"
    bare = "async def bare(conn, n=0):\n    return conn\n"
    cases = {
        # --- ATRIBUTE pe obiect (nu doar pe `db`: legarea e după adnotare) ---
        _in_fn("await db.execute('INSERT INTO patch_plans (a) VALUES (1) RETURNING id')"): {"attr"},
        _in_fn("await conn.execute('INSERT INTO t VALUES (1)')", "conn: Database"): {"attr"},
        _in_fn("await database.executemany('x', [])", "database: Database"): {"attr"},
        _in_fn("await db.fetchval('SELECT 1')"): {"attr"},
        _in_fn("async with db.transaction():\n    pass"): {"attr"},
        _in_fn("await db.pool.execute('x')"): {"attr", "unbound-call"},
        _in_fn("await db.notify('c', 'p')"): {"attr"},
        _in_fn("f = db.fetch\nawait f('SELECT 1')"): {"detached"},
        # --- TEXTUL SQL al unei citiri ---
        _in_fn("await db.fetch('INSERT INTO patch_plans (a) VALUES (1) RETURNING id')"):
            {"sql-kind"},
        _in_fn("await db.fetchrow('UPDATE patch_plans SET status = $1 RETURNING id', 'x')"):
            {"sql-kind"},
        _in_fn("await db.fetch('DELETE FROM findings')"): {"sql-kind"},
        _in_fn("await db.fetch('  -- nota\\nINSERT INTO t VALUES (1)')"): {"sql-kind"},
        _in_fn("await db.fetch('(SELECT 1)')"): {"sql-kind"},
        _in_fn("await db.fetch('WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x')"):
            {"sql-write"},
        _in_fn("await db.fetch('SELECT * INTO t2 FROM t')"): {"sql-write"},
        _in_fn("await db.fetch('SELECT id FROM t FOR UPDATE')"): {"sql-write"},
        _in_fn("await db.fetch('SELECT 1; DROP TABLE t')"): {"sql-write"},
        # --- verbul de scriere cu litere MICI / amestecate: `\b(...)\b` cu IGNORECASE ---
        _in_fn("await db.fetch('with x as (insert into t values (1) returning id) select * from x')"):
            {"sql-write"},
        _in_fn("await db.fetch('select id from t for update')"): {"sql-write"},
        _in_fn("await db.fetch('Select 1; Delete from t')"): {"sql-write"},
        _in_fn("await db.fetch('select * into t2 from t')"): {"sql-write"},
        # --- funcții ale schemei: un SELECT fără niciun verb de scriere în text ---
        _in_fn("await db.fetch('SELECT sentinel_emergency_retention()')"): {"sql-function"},
        _in_fn("await db.fetch('SELECT public.Sentinel_Drop_Old_Partitions (3)')"): {"sql-function"},
        _in_fn("await db.fetch('SELECT 1 FROM sentinel_ensure_partitions(3)')"): {"sql-function"},
        # --- `fetchmany` și restul suprafeței asyncpg ---
        _in_fn("await db.fetchmany('SELECT 1', [(1,)])"): {"attr"},
        _in_fn("await conn.fetchmany('SELECT 1', [(1,)])", "conn"): {"unbound-call"},
        _in_fn("c = await asyncpg.connect(dsn)\nawait c.fetchmany('INSERT INTO t VALUES ($1)', [(1,)])"):
            {"unbound-call"},
        # --- INTERPOGARE ILIZIBILĂ: cade închis ---
        _in_fn("q = 'SELECT 1'\nawait db.fetch(q)"): {"sql-unreadable"},
        _in_fn("await db.fetch('SELECT ' + cols)"): {"sql-unreadable"},
        _in_fn("await db.fetch('SELECT %s' % cols)"): {"sql-unreadable"},
        _in_fn("await db.fetch(f'{verb} id FROM t')"): {"sql-unreadable"},
        _in_fn("await db.fetch(f'SELECT {cols} FROM t')"): {"sql-unreadable"},
        _in_fn("await db.fetch(f'SELECT {pending_reboot_sql(alias)} FROM t')"): {"sql-unreadable"},
        _in_fn("await db.fetch(f'SELECT {other(\"f.\")} FROM t')"): {"sql-unreadable"},
        _in_fn("await db.fetch(*args)"): {"sql-unreadable"},
        _in_fn("await db.fetch()"): {"sql-unreadable"},
        _in_fn("await db.fetch(sql=q)"): {"sql-unreadable"},
        # --- OBIECTUL iese din locurile urmărite ---
        _in_fn("x = db"): {"escape"},
        _in_fn("return db"): {"escape"},
        _in_fn("return [db][0]"): {"escape"},
        _in_fn("await approvals.issue(db, 1)"): {"escape"},
        _in_fn("await repo.set_plan_status(db, 1, 'approved')"): {"escape"},
        _in_fn("await pending_reboot_sql(db)"): {"escape"},
        _in_fn("await bare(db)", before=bare): {"escape"},
        _in_fn("await helper(*[db])", before=helper): {"escape"},
        _in_fn("await helper(db, db)", before=helper): {"escape"},
        # --- LEGAREA are goluri dacă nu e completată ---
        _in_fn("await db.fetch('SELECT 1')", "db"): {"unbound", "unbound-call"},
        _in_fn("await db.execute('INSERT INTO t VALUES (1)')", "db"): {"unbound", "unbound-call"},
        _in_fn("await conn.execute('INSERT INTO t VALUES (1)')", "conn"): {"unbound-call"},
        _in_fn("d = Database(cfg)"): {"construct"},
        _in_fn("d = engine.Database(cfg)"): {"construct"},
    }
    for source, want in cases.items():
        _, _, findings = _database_scan(ast.parse(source))
        assert {k for k, _, _ in findings} == want, (source, findings)


def test_the_database_guard_admits_what_system_update_does_today():
    """Garda nu poate fi atât de strictă încât să fie ștearsă: citirile reale (inclusiv f-string-ul
    cu `pending_reboot_sql`, concatenarea implicită și parametrul redenumit) trebuie să treacă, la
    fel ca cele două scrieri permise ale lui `patches`."""
    helper = "async def helper(conn: Database, n=0):\n    return await conn.fetch('SELECT 1')\n"
    ok = [
        _in_fn("rows = await db.fetch('SELECT 1')"),
        _in_fn("row = await db.fetchrow('SELECT 1 WHERE x = $1', 1)"),
        _in_fn("await db.fetch('SELECT a, count(*) AS n '\n         'FROM findings WHERE status = $1', 1)"),
        _in_fn("await db.fetch('SELECT a ' + 'FROM t')"),
        _in_fn("await db.fetch('WITH x AS (SELECT 1) SELECT * FROM x')"),
        _in_fn("await db.fetch('\\n   select 1')"),
        _in_fn("await db.fetch(sql='SELECT 1')"),
        _in_fn("await db.fetch(f'''\n   SELECT f.id, {pending_reboot_sql(\"f.\")} AS p FROM findings f''', 1)"),
        _in_fn("await db.fetch(\"SELECT 1 FROM t WHERE k = 'update' AND j = 'it''s delete'\")"),
        _in_fn("await db.fetch('SELECT updated_at, created_at FROM t')"),
        _in_fn("await db.fetch('SELECT 1')", "db: Database | None"),
        _in_fn("await conn.fetch('SELECT 1')", "conn: Database"),
        _in_fn("await repo.store_plan(db, plan=1)\nawait repo.mark_plan_notified(db, 3)"),
        _in_fn("await helper(db, 1)\nawait helper(conn=db)", before=helper),
        "from sentinel.db.engine import Database\nfrom sentinel.db.repo import patches as p\n"
        "async def f(db: Database):\n    await p.store_plan(db)\n",
    ]
    for source in ok:
        _, _, findings = _database_scan(ast.parse(source))
        assert not findings, (source, findings)


#: Forme care DESCHID un «literal» fals pentru `_SQL_LITERAL`, deci ascund un verb de scriere real.
#: Fiecare e construită ca textul vechi (fără `_SQL_UNMODELLED`) să dea `None` — adică «citire».
_HIDING_WRITES = {
    "comentariu -- cu apostrof":
        "WITH w AS (SELECT 1 -- it's\n), x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT 'a' FROM w",
    "comentariu /* */ cu apostrof":
        "SELECT 1 /* ' */ , (WITH x AS (DELETE FROM t RETURNING id) SELECT 'z')",
    "E'..\\'' ": "SELECT 1 WHERE a = E'\\'' OR x IN (WITH w AS (INSERT INTO t VALUES (1) RETURNING id) SELECT 'b')",
    "e'..' cu litere mici": "SELECT 1 WHERE a = e'\\'' OR x IN (WITH w AS (DELETE FROM t RETURNING id) SELECT 'b')",
    "dolari $$": "SELECT $$ ' $$, (WITH w AS (INSERT INTO t VALUES (1) RETURNING id) SELECT 'z')",
    "dolari cu etichetă": "SELECT $q$ ' $q$, (WITH w AS (INSERT INTO t VALUES (1) RETURNING id) SELECT 'z')",
    "identificator cu apostrof":
        "SELECT 1 AS \"a'b\", (WITH w AS (INSERT INTO t VALUES (1) RETURNING id) SELECT 'z')",
    # cu `standard_conforming_strings = off` serverul citește `'a\''` ca pe un singur literal, iar
    # `_SQL_LITERAL` ca pe `'a\'` urmat de începutul altuia, care înghite INSERT-ul
    "backslash într-un literal": "SELECT 'a\\'' ; INSERT INTO t VALUES (1) ; SELECT 'b'",
}


def test_the_sql_gate_refuses_what_changes_what_a_literal_is():
    """`_SQL_LITERAL` scoate `'..'` ca să nu citească `status = 'update'` drept o scriere. Dar un
    apostrof într-un comentariu (`-- it's`, `/* ' */`), un `E'\\''`, un `$$ ' $$` sau un identificator
    `"a'b"` deschide un «literal» care înghite verbul de scriere de după el: `WITH w AS (INSERT ...)
    SELECT ...` trecea drept citire, iar operatorul n-ar fi aflat — comanda ar fi continuat să
    meargă. Doar un test al botului, care citește SQL-ul pe o altă cale, îl prindea întâmplător.
    Fiecare formă trebuie să pice ca `sql-unreadable` (nu ca `sql-write`: garda NU știe ce e
    literal acolo, deci nu pretinde că a citit verbul), atât direct cât și prin scanarea unei funcții.

    Controlul: valorile obișnuite (`'update'`, `'it''s'`, `interval '10 minutes'`, parametri `$1`) și
    cuvintele care se termină în `e` (`'active'`, `'type'`) rămân citiri. O valoare care e doar `e`
    sau se termină în ` e` pică și ea — fals pozitiv acceptat: cade închis, nu deschis."""
    for label, sql in _HIDING_WRITES.items():
        problem = _sql_problem(sql)
        assert problem is not None and problem[0] == "sql-unreadable", (label, problem)
        _, _, findings = _database_scan(ast.parse(_in_fn(f"await db.fetch({sql!r})")))
        assert {k for k, _, _ in findings} == {"sql-unreadable"}, (label, findings)
    # Un `E'..'` fără backslash nu ascunde nimic, dar garda nu-l modelează: pică și el (altfel
    # alternativa `E'` ar fi redundantă cu cea pentru `\`, iar ștergerea ei n-ar roși nimic).
    for sql in ("SELECT E'x'", "select e'x' from t", "SELECT 1 FROM t WHERE a=e'x'"):
        problem = _sql_problem(sql)
        assert problem is not None and problem[0] == "sql-unreadable", (sql, problem)
    for sql in ("SELECT 1 FROM t WHERE k = 'update' AND j = 'it''s delete'",
                "SELECT 1 FROM t WHERE ts > now() - interval '10 minutes' AND y = $1",
                "SELECT 1 FROM t WHERE x = ANY($1::text[]) AND y = $2::bigint",
                "SELECT 1 FROM t WHERE status = 'active' AND kind = 'type'",
                "select id, severity from detections where rule_family = 'intrusion'"):
        assert _sql_problem(sql) is None, sql


def _query_surface(cls: type) -> set[str]:
    """Metodele publice ale lui `cls` care iau o interogare (`query`/`command`/`sql`/`statement`) sau
    scriu/citesc în bloc (`copy_*`) — coroutine sau nu: `cursor(query)` nu e coroutină și e tot o
    ușă. Ce nu se poate citi pică, nu se sare."""
    out: set[str] = set()
    for name, member in inspect.getmembers(cls):
        if name.startswith("_") or not callable(member):
            continue
        try:
            params = set(inspect.signature(member).parameters)
        except (TypeError, ValueError) as exc:
            pytest.fail(f"nu pot citi semnătura `{cls.__module__}.{cls.__name__}.{name}` ({exc}): "
                        "suprafața de interogări nu se poate compara cu DB_METHODS")
        if params & {"query", "command", "sql", "statement"} or name.startswith("copy_"):
            out.add(name)
    return out


def test_db_methods_names_the_whole_query_surface_of_database_and_asyncpg():
    """`DB_METHODS` e ce face un apel pe un obiect NELEGAT să pice (`unbound-call`). I-a lipsit
    `fetchmany`, care există pe `asyncpg.Connection` și pe `Pool` (și pe gazdă, 0.30): o conexiune
    proprie și `c.fetchmany("INSERT ... RETURNING id", [...])` au trecut garda, cele cinci fișiere
    de teste și suita întreagă — o scriere în `patch_executions` fără ca nimic să roșească. Lista
    scrisă de mână nu poate fi crezută: se compară cu suprafața REALĂ, citită prin introspecție.
    O versiune nouă de asyncpg cu o metodă nouă face testul roșu: asta e rostul."""
    try:
        import asyncpg

        from sentinel.db.engine import Database
    except ImportError as exc:
        pytest.fail(f"nu pot importa suprafața de comparat ({exc}): DB_METHODS rămâne necontrolat")
    for cls in (Database, asyncpg.Connection, asyncpg.Pool):
        surface = _query_surface(cls)
        assert {"fetch", "fetchrow", "execute"} <= surface, (
            f"introspecția nu mai vede metodele de bază ale `{cls.__name__}` ({sorted(surface)}): "
            "nu pot compara DB_METHODS cu suprafața reală")
        missing = surface - DB_METHODS
        assert not missing, (f"`{cls.__module__}.{cls.__name__}` are {sorted(missing)} pe care DB_METHODS "
                             "nu le numește: un apel cu ele pe un obiect nelegat n-ar fi văzut. "
                             "Adaugă-le în DB_METHODS.")


def test_the_surface_reader_sees_a_method_that_takes_a_query_and_refuses_what_it_cannot_read():
    """Cititorul de suprafață trebuie să vadă metoda nouă a unei versiuni viitoare (un parametru
    `query`, o metodă `copy_*`, o metodă care nu e coroutină) și să NU ia drept interogare
    metodele de administrare; iar o semnătură ilizibilă pică, nu e sărită."""
    class Fake:
        async def fetchfoo(self, query, *args): ...
        def cursor(self, query): ...
        async def copy_weird(self, table_name): ...
        async def close(self, wait=None): ...
        async def _private(self, query): ...
        value = 3

    assert _query_surface(Fake) == {"fetchfoo", "cursor", "copy_weird"}

    class Unreadable:
        __signature__ = 42                             # `inspect.signature` ridică TypeError

        def __call__(self): ...

    class Opaque:
        fetch = Unreadable()

    with pytest.raises(pytest.fail.Exception, match="nu pot citi semnătura"):
        _query_surface(Opaque)


def test_every_database_method_name_is_refused_on_an_unbound_object_and_on_a_bound_one():
    """Fiecare nume din `DB_METHODS` trebuie să dea `unbound-call` pe un obiect fără adnotare și, pe
    unul legat, `attr` (în afară de `fetch`/`fetchrow`). Pe `execute` și `fetch` o făceau testele
    vechi; `fetchval` și `fetchmany` puteau lipsi din listă fără ca nimic să roșească."""
    for method in sorted(DB_METHODS):
        _, _, unbound = _database_scan(ast.parse(_in_fn(f"await conn.{method}('SELECT 1')", "conn")))
        assert {k for k, _, _ in unbound} == {"unbound-call"}, (method, unbound)
        _, _, bound = _database_scan(ast.parse(_in_fn(f"await db.{method}('SELECT 1')")))
        want = set() if method in DB_READ_ATTRS else {"attr"}
        assert {k for k, _, _ in bound} == want, (method, bound)


MIGRATIONS = ROOT / "sentinel" / "db" / "migrations"
_CREATE_FUNCTION = re.compile(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([A-Za-z_][\w.]*)\s*\(", re.IGNORECASE)


def test_every_callable_schema_function_is_named_by_the_function_gate():
    """Semnalul `sentinel_*(` din poarta 3 se bazează pe o convenție de nume. Dacă o migrare ar adăuga
    o funcție apelabilă fără prefixul ăla (`purge_old()`), `SELECT purge_old()` ar trece drept citire
    cât timp rolul `sentinel` poate șterge din tabelele modulului. Se citesc migrările: fiecare
    funcție care NU e trigger (un trigger nu se cheamă dintr-un `SELECT`) trebuie să fie potrivită de
    semnal. Un parser care nu mai găsește funcțiile ar trece pe gol, deci se cere și să le găsească."""
    seen: dict[str, bool] = {}                                   # nume -> e trigger
    files = sorted(MIGRATIONS.glob("*.sql"))
    assert files, f"nicio migrare în {MIGRATIONS}"
    for path in files:
        text = path.read_text(encoding="utf-8")
        for m in _CREATE_FUNCTION.finditer(text):
            head = re.split(r"\bAS\s+\$|\bCREATE\b", text[m.end():], maxsplit=1, flags=re.IGNORECASE)[0]
            returns = re.search(r"\bRETURNS\s+(\w+)", head, re.IGNORECASE)
            seen[m.group(1).split(".")[-1]] = bool(returns and returns.group(1).lower() == "trigger")
    assert any(n.startswith("sentinel_") and not trig for n, trig in seen.items()), (
        "parserul de migrări nu mai găsește nicio funcție `sentinel_*` apelabilă", seen)
    assert any(trig for trig in seen.values()), "parserul nu mai recunoaște nicio funcție trigger"
    callable_names = sorted(n for n, trig in seen.items() if not trig)
    unnamed = [n for n in callable_names if not _SQL_SCHEMA_FUNCTION.search(f"{n}()")]
    assert not unnamed, (f"funcții apelabile din migrări pe care poarta 3 nu le numește: {unnamed}. "
                         "Extinde _SQL_SCHEMA_FUNCTION în aceeași schimbare, sau dă-le prefixul `sentinel_`.")


# ---------------------------------------------------------------------------
# Singura interpolare permisă: să fie funcția reală, și numai ea
# ---------------------------------------------------------------------------
def _rebindings(tree: ast.Module, current: str = THIS_MODULE) -> list[tuple[int, str, str]]:
    """(linie, nume, cum) pentru orice legare a numelor din `SQL_INTERPOLATIONS` ALTFEL decât prin
    `from <modulul real> import <nume>` (fără alias), în ORICE scop. Plus lipsa importului.

    Poarta 3 citește un f-string cu `{pending_reboot_sql("f.")}` ca pe «funcția reală», dar nimic
    din AST nu spune care funcție e legată la numele ăla: un `def pending_reboot_sql(alias): return
    "... (INSERT ... RETURNING 1) w, (SELECT false"` la nivel de modul lasă importul (și lista
    modulelor, și verificarea de intrare învechită) mulțumite, iar f-string-ul se citea ca un loc
    gol. Orice formă care leagă un nume — definiție, atribuire, parametru, `for`/`with`/`except as`,
    `:=`, `global`, `match`, `del`, alt import, `import *` — e o constatare."""
    names = set(SQL_INTERPOLATIONS)
    out: list[tuple[int, str, str]] = []
    imported: set[str] = set()
    for n in ast.walk(tree):
        line = getattr(n, "lineno", 0)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name in names:
            out.append((line, n.name, f"definit ca {type(n).__name__}"))
        elif isinstance(n, ast.arg) and n.arg in names:
            out.append((line, n.arg, "parametru"))
        elif isinstance(n, ast.Name) and n.id in names and not isinstance(n.ctx, ast.Load):
            out.append((line, n.id, "atribuit sau șters"))
        elif isinstance(n, ast.ExceptHandler) and n.name in names:
            out.append((line, n.name, "`except ... as`"))
        elif isinstance(n, (ast.Global, ast.Nonlocal)) and names & set(n.names):
            out.append((line, ",".join(sorted(names & set(n.names))), "global/nonlocal"))
        elif isinstance(n, (getattr(ast, "MatchAs", ()), getattr(ast, "MatchStar", ()))) and n.name in names:
            out.append((line, n.name, "captură `match`"))
        elif isinstance(n, getattr(ast, "MatchMapping", ())) and n.rest in names:
            out.append((line, n.rest, "captură `match`"))
        elif isinstance(n, ast.Import):
            out += [(line, a.asname or a.name, "`import`") for a in n.names
                    if (a.asname or a.name.split(".")[0]) in names]
        elif isinstance(n, ast.ImportFrom):
            home = _absolute(n, current) if n.level < len(current.split(".")) else ""
            for a in n.names:
                if a.name == "*":
                    out.append((line, "*", f"`from {home or '?'} import *` poate lega orice nume"))
                elif (a.asname or a.name) in names:
                    bound = a.asname or a.name
                    if home == SQL_INTERPOLATIONS[bound][0] and a.name == bound and a.asname in (None, bound):
                        imported.add(bound)
                    else:
                        out.append((line, bound, f"importat din `{home or '?'}` ca `{a.name}`"))
    out += [(0, name, f"nu mai e importat din `{SQL_INTERPOLATIONS[name][0]}`") for name in sorted(names - imported)]
    return sorted(out)


def test_system_update_binds_the_sql_interpolation_only_by_the_real_import():
    """Singura interpolare din SQL e `pending_reboot_sql`, citită de poartă drept funcția reală din
    `findings`. Dacă modulul și-ar defini propria `pending_reboot_sql` (sau ar umbri-o într-o
    funcție), poarta ar scana un text care nu e al funcției reale, iar un verb de scriere ar trece.
    Garda cere ca numele să fie legat DOAR de importul din modulul real."""
    bad = _rebindings(_tree(SYSTEM_UPDATE))
    assert not bad, ("system_update.py leagă altfel o interpolare SQL permisă: "
                     + "; ".join(f"linia {line}: {name} ({how})" for line, name, how in bad))


def test_the_rebinding_check_sees_every_way_to_shadow_the_interpolation_and_admits_the_real_import():
    """Fiecare formă de umbrire trebuie să pice; importul real, în orice formă legitimă (modul, funcție,
    relativ), trebuie să treacă — garda nu poate fi atât de strictă încât să fie ștearsă."""
    head = "from sentinel.db.repo.findings import pending_reboot_sql\n"
    shadows = [
        "def pending_reboot_sql(alias):\n    return 'false'",
        "async def pending_reboot_sql(alias):\n    return 'false'",
        "class pending_reboot_sql: ...",
        "pending_reboot_sql = lambda alias: 'false'",
        "pending_reboot_sql: object = None",
        "pending_reboot_sql += 'x'",
        "for pending_reboot_sql in range(3): pass",
        "with open('x') as pending_reboot_sql: pass",
        "def g(pending_reboot_sql): pass",
        "def g(*, pending_reboot_sql=None): pass",
        "g = lambda pending_reboot_sql: 1",
        "try:\n    pass\nexcept Exception as pending_reboot_sql:\n    pass",
        "def g():\n    global pending_reboot_sql",
        "(pending_reboot_sql := 1)",
        "del pending_reboot_sql",
        "[1 for pending_reboot_sql in range(2)]",
        "match 1:\n    case pending_reboot_sql:\n        pass",
        "import pending_reboot_sql",
        "import os as pending_reboot_sql",
        "from os import path as pending_reboot_sql",
        "from other import pending_reboot_sql",
        "from sentinel.db.repo.findings import FIX_PENDING_REBOOT as pending_reboot_sql",
        "from sentinel.db.repo.findings import pending_reboot_sql as other",
        "from sentinel.db.repo.findings import *",
        "def g():\n    from other import pending_reboot_sql",
    ]
    for body in shadows:
        # `as other` lasă `pending_reboot_sql` din head legat corect: forma aia nu e o umbrire a
        # numelui, ci un alias — se prinde doar dacă nu mai există importul simplu.
        source = body if body.endswith("as other") else head + body
        assert _rebindings(ast.parse(source)), body
    assert _rebindings(ast.parse("x = 1")), "fără niciun import, numele nu e legat de nimic real"
    for source in (head, head + "async def f():\n    return pending_reboot_sql('f.')",
                   "def g():\n    from sentinel.db.repo.findings import pending_reboot_sql\n    return pending_reboot_sql('')",
                   "from ..db.repo.findings import pending_reboot_sql",
                   head + "x.pending_reboot_sql = 1\nf(pending_reboot_sql=2)\npending_reboot_sql('')"):
        assert not _rebindings(ast.parse(source)), source


def test_the_interpolated_sql_is_scanned_as_the_real_function_produces_it(monkeypatch):
    """`_sql_text` nu înlocuiește interpolarea cu un surogat: cheamă funcția reală din `findings` și
    scanează ce întoarce. Dacă ea ar începe să producă un verb de scriere, sau un comentariu, sau ar
    ridica, poarta ar vedea asta — nu un `<>` inofensiv."""
    snippet = _in_fn("await db.fetch(f'SELECT f.id, {pending_reboot_sql(\"f.\")} AS p FROM findings f', 1)")
    call = next(n for n in ast.walk(ast.parse(snippet)) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and n.func.attr == "fetch")
    text = _sql_text(call.args[0])
    assert text is not None and pending_reboot_sql("f.") in text, text
    for alias in ("", "f.", "findings."):
        assert _sql_problem(f"SELECT {pending_reboot_sql(alias)} AS p FROM findings f") is None, alias

    def boom(alias):
        raise RuntimeError("x")
    cases = {
        "un verb de scriere": (lambda a: "false AS p FROM (INSERT INTO patch_executions (plan_id) "
                                         "VALUES (1) RETURNING 1) w, (SELECT false", "sql-write"),
        "un comentariu cu apostrof": (lambda a: "false /* ' */", "sql-unreadable"),
        "o funcție a schemei": (lambda a: "sentinel_emergency_retention()", "sql-function"),
        "o funcție care ridică": (boom, "sql-unreadable"),
        "ceva care nu e șir": (lambda a: 42, "sql-unreadable"),
    }
    for label, (produce, want) in cases.items():
        with monkeypatch.context() as m:
            m.setitem(SQL_INTERPOLATIONS, "pending_reboot_sql", ("sentinel.db.repo.findings", produce))
            _, _, findings = _database_scan(ast.parse(snippet))
        assert {k for k, _, _ in findings} == {want}, (label, findings)
    _, _, findings = _database_scan(ast.parse(snippet))        # monkeypatch s-a retras: iar curat
    assert not findings, findings


#: Tot ce pornește un proces. Forma `shell` e cea prin care o gardă pe argv se ocolește: un singur
#: șir cu `;` în el nu are un «program în față» de verificat.
SPAWN_NAMES = {"create_subprocess_exec", "create_subprocess_shell", "subprocess_exec",
               "subprocess_shell"}
#: Tot ce din `os` pornește un proces sau înlocuiește procesul curent: `system`/`popen` (shell),
#: `posix_spawn*`, familia `spawn*`, familia `exec*`, `fork`/`forkpty`. Prima versiune avea doar
#: primele două, iar un `os.posix_spawn(...)` a trecut prin toată suita. Numele sunt scrise explicit
#: în testul de mai jos, ca o greșeală aici să nu se repete în ambele locuri.
_EXEC_SUFFIXES = ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")
OS_SPAWN_ATTRS = ({"system", "popen", "posix_spawn", "posix_spawnp", "fork", "forkpty"}
                  | {f"spawn{s}" for s in _EXEC_SUFFIXES} | {f"exec{s}" for s in _EXEC_SUFFIXES})


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
            if any(a.name == "*" for a in node.names):     # `from os import *`: toate numele, fără alias
                bare |= OS_SPAWN_ATTRS
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        on_os = (isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                 and n.func.value.id in os_names and n.func.attr in OS_SPAWN_ATTRS)
        # `<orice>.os.system(...)`: `os`-ul re-exportat al unui modul importat (`os_packages.os`).
        # `_spawns` cerea ca baza să fie un `Name` din `os_names`, deci lanțul era invizibil.
        via_module = (isinstance(n.func, ast.Attribute) and n.func.attr in OS_SPAWN_ATTRS
                      and isinstance(n.func.value, ast.Attribute) and n.func.value.attr in os_names)
        name = getattr(n.func, "attr", None) if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", None)
        if on_os or via_module or (name in SPAWN_NAMES) or (isinstance(n.func, ast.Name) and n.func.id in bare):
            out.append(n)
    return out


#: Modulele standard prin care un cod poate porni procese, umbla în fișiere sau ajunge la altceva,
#: dacă le ia de pe un modul `sentinel.*` care le importă: `os_packages.os`, `checks.subprocess`.
REACH_ATTRS = frozenset({"os", "asyncio", "shutil", "subprocess", "sys", "posix"})


def _reach_through(tree: ast.Module, current: str = THIS_MODULE) -> tuple[set[str], list[tuple[int, str]]]:
    """(numele locale ale modulelor `sentinel.*`, `(linie, expresie)` pentru fiecare `<modul>.os` /
    `.asyncio` / `.shutil` / `.subprocess` / `.sys` / `.posix`).

    Poarta 4 numără procesele pornite și se uită la `os.X` cu `os` importat AICI. Dar `os_packages`
    importă `os` și `shutil` la nivel de modul, deci `os_packages.os.posix_spawn(...)` pornea un
    proces fără ca importul lui `os` din `system_update` să existe. Lista de module permise nu ajută:
    `os_packages` e pe ea, legitim. Se semnalează ORICE acces de atribut care ia un modul standard
    de pe un modul nostru — mai larg decât un lanț `.os.<spawn>`, deci prinde și `.subprocess.run`
    și `.shutil.rmtree`, pe care `_spawns` nu le numără."""
    ours: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            ours |= {a.asname or a.name.split(".")[0] for a in node.names if _is_ours(a.name)}
        elif isinstance(node, ast.ImportFrom) and node.level < len(current.split(".")) \
                and _is_ours(_absolute(node, current)):
            ours |= {a.asname or a.name for a in node.names}
    found: list[tuple[int, str]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and n.attr in REACH_ATTRS:
            base = n.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id in ours:
                found.append((n.lineno, ast.unparse(n)))
    return ours, sorted(found)


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


def test_the_spawn_detector_knows_every_way_os_starts_or_replaces_a_process():
    """`os.posix_spawn(...)`, `os.spawnv(...)`, `os.execv(...)` și `os.fork()` pornesc un proces fără
    să treacă prin `_run`, deci fără lista `rpm`/`dpkg-query`: o aplicare fără nicio semnătură. Lista
    veche avea doar `system` și `popen`, iar numărătoarea («un singur proces») a rămas verde. Fiecare
    nume, pe fiecare formă de import: `os.X`, `import os as o`, `from os import X [as Y]`, `*`."""
    names = ("system", "popen", "posix_spawn", "posix_spawnp", "fork", "forkpty",
             "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
             "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe")
    assert OS_SPAWN_ATTRS == set(names), (OS_SPAWN_ATTRS ^ set(names))
    for name in names:
        for source in (f"os.{name}('x')", f"import os as o\no.{name}('x')",
                       f"from os import {name}\n{name}('x')", f"from os import {name} as sh\nsh('x')",
                       f"from os import *\n{name}('x')"):
            assert len(_spawns(ast.parse(source))) == 1, source
    # Numele din `os` care NU pornesc un proces rămân în pace, la fel ca aceleași nume pe alt obiect
    # sau chemate gol fără să fi fost aduse din `os`.
    assert not _spawns(ast.parse(
        "os.getpid()\nos.environ.get('X')\nos.path.join('a')\nself.fork()\nexecv('x')\nfork()\n"
        "pool.posix_spawn('x')\nloop.execv('x')\nfrom os import getpid\ngetpid()"))


def test_the_spawn_detector_sees_the_os_a_sentinel_module_re_exports():
    """`os_packages` importă `os` și `shutil` la nivel de modul. `os_packages.os.system("dnf -y
    update")` și `os_packages.os.posix_spawn(...)` porneau un proces fără ca `system_update` să
    importe `os`: `_spawns` cerea ca baza apelului să fie un `Name` din `os_names`. L-a prins doar un
    regex de text (`os.system(`) dintr-un test vecin — iar `posix_spawn` nu l-a prins nimic.
    Fiecare formă trebuie numărată ca proces ȘI semnalată ca ajungere-prin; controalele (`os` propriu,
    `asyncio.subprocess.PIPE`, o funcție a modulului) nu."""
    scan = "from sentinel.scan import os_packages\n"
    for call in ("os_packages.os.system('dnf -y update')", "os_packages.os.posix_spawn('x', [], {})",
                 "os_packages.os.execv('x', [])", "os_packages.os.fork()"):
        tree = ast.parse(scan + call)
        assert len(_spawns(tree)) == 1, call
        assert _reach_through(tree)[1], call
    for call, spawned in (("os_packages.subprocess.run(['dnf'])", 0),
                          ("os_packages.shutil.rmtree('/x')", 0),
                          ("os_packages.asyncio.create_subprocess_shell('x')", 1),
                          ("os_packages.sys.modules['subprocess']", 0)):
        tree = ast.parse(scan + call)
        assert len(_spawns(tree)) == spawned, call
        assert _reach_through(tree)[1], call
    for source in ("import sentinel.scan.os_packages\nsentinel.scan.os_packages.shutil.rmtree('/x')",
                   "from sentinel.scan import os_packages as osp\nosp.os.environ",
                   "from sentinel.patch import checks\nchecks.os",
                   "from . import checks\nchecks.subprocess",
                   "from sentinel.scan import os_packages\nx = os_packages\nx.os.system('y')"):
        tree = ast.parse(source)
        ours, found = _reach_through(tree)
        assert ours and (found or _spawns(tree)), source
    # Controale: ce modulul face azi și nu e ajungere-prin.
    for source in ("import os\nimport asyncio\nos.environ\nasyncio.subprocess.PIPE\nasyncio.wait_for(x)",
                   "from sentinel.scan import os_packages\nos_packages.scanner_for('rhel')",
                   "from sentinel.patch import checks\nchecks._rpm_evr_cmp(1, 2)\nx.os.getpid()",
                   "import os\nos.path.join('a')"):
        tree = ast.parse(source)
        assert not _reach_through(tree)[1] and not _spawns(tree), source
    assert _reach_through(ast.parse("from sentinel.scan import os_packages\nfrom os import path"))[0] \
        == {"os_packages"}


def test_neither_update_module_reaches_a_process_or_a_file_through_a_sentinel_module():
    """Poarta 4 pentru codul real: nicio expresie `<modul sentinel>.os|asyncio|shutil|subprocess|sys|
    posix` în `system_update` sau `update_view`, și niciun proces pornit în `update_view`. Garda
    trebuie să VADĂ modulele noastre importate (altfel nu ar găsi nimic nici dacă ar exista ceva)."""
    for path, current in ((SYSTEM_UPDATE, THIS_MODULE), (UPDATE_VIEW, UPDATE_VIEW_MODULE)):
        tree = _tree(path)
        ours, found = _reach_through(tree, current)
        assert ours, f"{path.name}: garda nu vede niciun modul `sentinel.*` importat — ar trece pe gol"
        assert not found, f"{path.name} ia un modul standard de pe un modul al nostru: {found}"
    assert not _spawns(_tree(UPDATE_VIEW)), "update_view.py pornește un proces"


#: Ce flag-uri are voie să primească fiecare program, și ce mod trebuie să fie argv[1]. Nu o listă de
#: flag-uri INTERZISE: `rpm` are `--eval`/`-E`, `--define`/`-D`, `--macros`, `--rcfile`, `--pipe` (rulează
#: o comandă), `--setperms`/`-i`/`-e` (schimbă gazda) și o listă care crește cu versiunea — o listă
#: de interzise ar fi mereu cu un cuvânt în urmă. Ce nu e aici pică.
READ_ONLY_MODE = {"rpm": "-q", "dpkg-query": "-W"}
READ_ONLY_FLAGS = {"rpm": frozenset({"-q", "--qf", "--whatprovides"}),
                   "dpkg-query": frozenset({"-W", "-f"})}
#: `%(...)` și `%{lua:...}` execută cod când `rpm` expandează o macro (`rpm --eval "%(id)"`).
_MACRO_EXEC = re.compile(r"%\(|%\{\s*lua\s*:", re.IGNORECASE)


def _string_constants(tree: ast.Module) -> dict[str, list[str]]:
    """Constantele de modul care sunt șiruri sau colecții de șiruri: `_RPM_QF`, `_DPKG_QF`,
    `_INSTALLONLY_PROVIDES`. Pe ele argv-ul le pasează cu numele, nu cu valoarea."""
    out: dict[str, list[str]] = {}
    for node in tree.body:
        target, value = ((node.targets[0], node.value) if isinstance(node, ast.Assign) and len(node.targets) == 1
                         else (node.target, node.value) if isinstance(node, ast.AnnAssign) and node.value
                         else (None, None))
        if not isinstance(target, ast.Name):
            continue
        try:
            got = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            continue
        if isinstance(got, str):
            out[target.id] = [got]
        elif isinstance(got, (tuple, list)) and got and all(isinstance(x, str) for x in got):
            out[target.id] = list(got)
    return out


def _name_filtered_lists(tree: ast.Module) -> set[str]:
    """Numele legate O SINGURĂ dată, dintr-o expresie care trece fiecare element prin
    `_NAME_RE.fullmatch` (`safe = sorted({n for n in names if _NAME_RE.fullmatch(n)})`). Ele pot fi
    desfăcute într-un argv fără să poată deveni un flag: `_NAME_RE` începe cu o cifră sau o literă
    (verificat separat, pe expresia regulată din cod)."""
    stores: dict[str, int] = {}
    filtered: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            stores[n.id] = stores.get(n.id, 0) + 1
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) \
                and "_NAME_RE.fullmatch(" in ast.unparse(n.value):
            filtered.add(n.targets[0].id)
    return {name for name in filtered if stores.get(name) == 1}


def _name_re_problems(tree: ast.Module) -> list[str]:
    """`_NAME_RE` trebuie citit din cod și să nu accepte nimic care arată a opțiune sau a macro."""
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            if isinstance(target, ast.Name) and target.id == "_NAME_RE":
                call = node.value
                if not (isinstance(call, ast.Call) and call.args and isinstance(call.args[0], ast.Constant)
                        and isinstance(call.args[0].value, str)):
                    return ["`_NAME_RE` nu e `re.compile(<literal>)`: nu-l pot citi"]
                rx = re.compile(call.args[0].value)
                return [f"`_NAME_RE` acceptă {probe!r}" for probe in
                        ("-D", "--eval", "-E", "-q", "%(id)", "a%(id)", "a b", "--pipe=x", "a\n-D", "")
                        if rx.fullmatch(probe)]
    return ["`_NAME_RE` nu mai e definit la nivel de modul"]


def _run_problems(tree: ast.Module) -> list[tuple[int, str]]:
    """(linie, problemă) pentru fiecare `_run(...)`: argv-ul trebuie să fie o listă literală, cu un
    program de citire în față, modul lui ca argv[1], doar flag-uri din `READ_ONLY_FLAGS`, nicio
    constantă care expandează o macro, iar orice element necunoscut (un nume neresolvabil, un f-string,
    o listă nefiltrată prin `_NAME_RE`) e o problemă — nu se sare."""
    consts = _string_constants(tree)
    safe = _name_filtered_lists(tree)
    out: list[tuple[int, str]] = []
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == "_run"):
        argv = call.args[0] if call.args else None
        if not (isinstance(argv, ast.List) and argv.elts and isinstance(argv.elts[0], ast.Constant)):
            out.append((call.lineno, "argv-ul nu e o listă literală cu programul în față"))
            continue
        prog = argv.elts[0].value
        if prog not in READ_ONLY_PROGRAMS or prog not in READ_ONLY_MODE:
            out.append((call.lineno, f"{prog!r} nu e o interogare de citire"))
            continue
        mode = argv.elts[1] if len(argv.elts) > 1 else None
        if not (isinstance(mode, ast.Constant) and mode.value == READ_ONLY_MODE[prog]):
            out.append((call.lineno, f"argv[1] al lui {prog!r} nu e {READ_ONLY_MODE[prog]!r} (e "
                                     f"{ast.unparse(mode) if mode is not None else 'absent'})"))
        for el in argv.elts[1:]:
            if isinstance(el, ast.Constant) and isinstance(el.value, str):
                values = [el.value]
            elif isinstance(el, ast.Name) and el.id in consts:
                values = consts[el.id]
            elif isinstance(el, ast.Starred) and isinstance(el.value, ast.Name) and el.value.id in consts:
                values = consts[el.value.id]
            elif isinstance(el, ast.Starred) and isinstance(el.value, ast.Name) and el.value.id in safe:
                continue                                  # trecut prin `_NAME_RE`; regexul e verificat separat
            else:
                out.append((call.lineno, f"element pe care garda nu-l poate citi: {ast.unparse(el)}"))
                continue
            for v in values:
                if v.startswith("-") and v not in READ_ONLY_FLAGS[prog]:
                    out.append((call.lineno, f"flag în afara listei pentru {prog}: {v!r}"))
                if _MACRO_EXEC.search(v):
                    out.append((call.lineno, f"constantă care expandează o macro (rulează cod): {v!r}"))
    return out


def test_the_only_commands_system_update_runs_itself_are_read_only_queries():
    """Singurul loc care pornește un proces e `_run`, iar apelanții lui dau doar `rpm`/`dpkg-query`.
    Un `_run(["dnf", ...])` ar fi o aplicare fără nicio semnătură; la fel `_run(["rpm", "--eval",
    "%(dnf -y update)"])`, care trece de «programul e rpm» și rulează un shell ca utilizatorul
    `sentinel` (în grupul `docker`, deci root prin soclu)."""
    tree = _tree(SYSTEM_UPDATE)
    spawns = _spawns(tree)
    assert len(spawns) == 1, "procese pornite în mai mult de un loc"
    assert getattr(spawns[0].func, "attr", "") == "create_subprocess_exec", \
        "singurul proces pornit trebuie să fie forma cu argv, nu cea cu shell"
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "_run"]
    assert len(calls) >= 3, "garda nu mai vede apelurile lui _run"
    bad = _run_problems(tree) + [(0, p) for p in _name_re_problems(tree)]
    assert not bad, "\n".join(f"linia {line}: {what}" for line, what in bad)
    assert _name_filtered_lists(tree), "nicio listă filtrată prin `_NAME_RE`: garda nu mai vede `safe`"


def test_the_argv_gate_refuses_a_read_only_program_that_is_told_to_run_something():
    """`READ_ONLY_PROGRAMS` verifica doar `argv[0]`. Dovedit pe gazdă: `rpm --eval "%(echo X)"`
    rulează `echo X` (RPM 4.16); `--qf` nu expandează macro-uri, deci interogarea de azi era în
    siguranță, dar `_run(["rpm", "--eval", "%(dnf -y update)"])` trecea garda, cele cinci fișiere și
    suita întreagă. Fiecare formă trebuie să pice; formele reale ale modulului trebuie să treacă."""
    head = ("_RPM_QF = '%{NAME}\\\\t%{VERSION}\\\\n'\n_PROVIDES = ('installonlypkg(kernel)', 'multiversion(kernel)')\n"
            "_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}')\n"
            "async def f(names, flag, other):\n"
            "    safe = sorted({n for n in names if _NAME_RE.fullmatch(n)})\n")

    def problems(argv: str) -> list[tuple[int, str]]:
        return _run_problems(ast.parse(head + f"    await _run({argv})\n"))
    for argv in ('["rpm", "--eval", "%(dnf -y update)"]',
                 '["rpm", "-q", "--eval", "%(echo X)"]',
                 '["rpm", "-q", "-E", "%(echo X)"]',
                 '["rpm", "-q", "--qf", "%(echo X)", *safe]',
                 '["rpm", "-q", "--qf", "%{lua:os.execute(\'x\')}", *safe]',
                 '["rpm", "-q", "--define", "x %(id)"]',
                 '["rpm", "-q", "-D", "x 1", *safe]',
                 '["rpm", "-q", "--macros", "/tmp/m", *safe]',
                 '["rpm", "-q", "--rcfile", "/tmp/r", *safe]',
                 '["rpm", "-q", "--pipe", "sh", *safe]',
                 '["rpm", "-i", "x.rpm"]',
                 '["rpm", "-e", "kernel"]',
                 '["rpm", "--qf", "%{NAME}", "-q"]',
                 '["rpm", "-q", *names]',
                 '["rpm", "-q", flag]',
                 '["rpm", "-q", f"--{other}"]',
                 '["rpm", other]',
                 '["rpm"]',
                 '["dpkg-query", "-W", "-f", "x", "--eval"]',
                 '["dpkg-query", "-L", "x"]',
                 '["dpkg-query", "-W", *names]',
                 '["dnf", "-y", "update"]',
                 '[other, "-q"]',
                 'other'):
        assert problems(argv), argv
    for argv in ('["rpm", "-q", "--qf", _RPM_QF, *safe]',
                 '["rpm", "-q", "--whatprovides", *_PROVIDES, "rpm", "--qf", "%{NAME}\\\\n"]',
                 '["dpkg-query", "-W", "-f", "${Package}\\\\n", *safe]'):
        assert not problems(argv), (argv, problems(argv))
    assert _name_re_problems(ast.parse(head)) == []
    for rx in ("[A-Za-z0-9._+%(-][A-Za-z0-9._+-]{0,127}", "[A-Za-z0-9._+-]{0,127}", "[-A-Za-z0-9]+",
               "\\S+", ".+"):
        assert _name_re_problems(ast.parse(f"_NAME_RE = re.compile(r'{rx}')")), rx
    assert _name_re_problems(ast.parse("x = 1")) and _name_re_problems(ast.parse("_NAME_RE = make()"))
    # `safe` care nu vine dintr-un filtru, sau e rescris, nu mai e de încredere
    for rebind in ("    safe = names\n", "    safe = list(names)\n    safe = sorted(safe)\n"):
        src = head.replace("    safe = sorted({n for n in names if _NAME_RE.fullmatch(n)})\n", rebind)
        assert _run_problems(ast.parse(src + '    await _run(["rpm", "-q", *safe])\n')), rebind
    src = head + '    safe = names\n    await _run(["rpm", "-q", *safe])\n'
    assert _run_problems(ast.parse(src)), "o a doua legare a lui `safe` trebuie să-l scoată din încredere"


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
