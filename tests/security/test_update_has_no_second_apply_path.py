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

  1. fiecare modul `sentinel.*` importat e pe o listă numită (`ALLOWED_SENTINEL_MODULES`);
  2. pe obiectul `Database` se cheamă doar `fetch`/`fetchrow`, iar obiectul nu iese din
     funcțiile care îl primesc ca `Database`;
  3. textul fiecărei interogări e un literal care începe cu `SELECT`/`WITH` și nu conține
     niciun verb de scriere — iar ce nu se poate citi pică, nu trece;
  4. orice formă de a porni un proces din `os` (`posix_spawn`, `spawn*`, `exec*`, `fork`).

Garda mărginește FELUL instrucțiunii, nu efectul ei: un `SELECT` care cheamă o funcție cu
efecte secundare (`pg_terminate_backend`, `nextval`) nu se vede de aici. Limita reală e rolul
bazei de date, nu acest fișier.
"""
from __future__ import annotations

import ast
import re
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
#: într-o funcție al cărei parametru n-are `: Database`).
DB_METHODS = frozenset({"fetch", "fetchrow", "fetchval", "execute", "executemany", "transaction",
                        "acquire", "prepare", "cursor", "notify", "listen",
                        "copy_records_to_table", "copy_to_table"})

SQL_READ_KEYWORDS = frozenset({"SELECT", "WITH"})

#: Singura interpolare permisă într-un f-string de SQL: expresia CONSTANTĂ a lui
#: `findings.pending_reboot_sql` (vezi comentariul de la `load_candidates`). Orice altceva
#: interpolat — un nume de coloană, un verb — face textul necitibil pentru gardă.
SQL_INTERPOLATIONS = frozenset({"pending_reboot_sql"})

#: Verbe care schimbă baza sau schema. `WITH x AS (INSERT ... RETURNING ...) SELECT ...` începe cu
#: un cuvânt de citire și scrie; `SELECT ... INTO t` creează o tabelă; `FOR UPDATE` ia lacăte. Se
#: caută în text DUPĂ ce literalele între apostrofuri sunt scoase (`status = 'update'` e o valoare).
_SQL_WRITE_WORD = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|ALTER|DROP|CREATE|GRANT|REVOKE|COPY|INTO)\b", re.IGNORECASE)
_SQL_LITERAL = re.compile(r"'(?:[^']|'')*'")
_SQL_HEAD = re.compile(r"\s*([A-Za-z]+)\b")


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
    interpolări sunt cele din `SQL_INTERPOLATIONS` (înlocuite cu `<>`, ca să nu devină cuvinte)."""
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
                parts.append("<>")
            else:
                return None
        return "".join(parts)
    return None


def _sql_problem(text: str) -> tuple[str, str] | None:
    """(fel, detaliu) dacă `text` nu e o citire; `None` dacă e. Primul cuvânt trebuie să fie
    `SELECT`/`WITH` (un comentariu sau o paranteză în față îl ascund, deci pică: un om decide), iar
    în rest nu apare niciun verb de scriere."""
    shown = " ".join(text.split())[:70]
    head = _SQL_HEAD.match(text)
    if head is None or head.group(1).upper() not in SQL_READ_KEYWORDS:
        return "sql-kind", shown
    hit = _SQL_WRITE_WORD.search(_SQL_LITERAL.sub("''", text))
    if hit:
        return "sql-write", f"{hit.group(1).upper()} în: {shown}"
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
                      "interpolare). Scrie-o ca literal; dacă chiar trebuie construită, un om hotărăște "
                      "și extinde garda, nu o ocolește.",
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
    assert bound, "nicio funcție nu mai primește un parametru adnotat `Database` — garda nu vede nimic"
    raw = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
           and n.func.attr in DB_READ_ATTRS]
    assert n_reads and n_reads == len(raw), (
        f"garda a văzut {n_reads} citiri din {len(raw)} apeluri `.fetch`/`.fetchrow`: o legare a pierdut un nume")
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
