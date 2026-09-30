"""Ce plafon cere fiecare apel dnf din `sentinel/scan/os_packages.py`, citit din AST.

Modul de ajutor, nu fișier de teste (numele începe cu `_`, pytest nu-l colectează).
E importat de `test_scan_cache_dir.py` și de `test_scan_dnf_advisories.py` ca
`from tests.unit._dnf_ceilings import ...` — aceeași cale ca `tests.unit.test_shipper`
în `test_aggregator_auth_parity.py`. Există într-un singur loc fiindcă a fost copiat
o dată: două teste citeau sursa ca text, tăiată între două nume de funcții
(`source.index("async def _uncovered_advisories")` până la
`"\nasync def _installed_advisory_check"`), iar o simplă mutare a funcțiilor le
strica, fără ca vreun plafon să se schimbe. Două copii ale verificatorului ar fi
adus înapoi exact asta: una învață un rol nou, cealaltă nu.

Eșecul pe care îl previne, pentru operator: un `timeout=120` scris de mână la un apel
dnf, cu o constantă alături care spune altceva. Așa a apărut moneda aruncată din
21 august 2026 — rulări reale între 82 și 120 s față de un plafon de 120 s, scanarea
picând noaptea, lista de vulnerabilități înghețată fără să afle cineva.

Un apel se recunoaște după ce e SCRIS în argv, nu după locul lui în fișier: nici
ordinea funcțiilor, nici așezarea în pagină a apelului nu contează.
"""
from __future__ import annotations

import ast

# Rol -> constanta pe care apelul respectiv trebuie s-o ceară ca `timeout=`.
DNF_CEILINGS = {
    "main": "TIMEOUT_S",             # `list cves --security`, fără `-C`
    "control": "CONTROL_TIMEOUT_S",  # singurul cu `--installed`
    "advisory": "ADVISORY_TIMEOUT_S",  # `-C`, fără `cves`, fără `--installed`
}

# Predicatele împart argv-urile după două steaguri, `-C` și `--installed`, care nu
# se pot suprapune: `main` cere absența AMBELOR, `control` cere `--installed`,
# `advisory` cere `-C` și absența lui `--installed`. Un al patrulea apel care nu
# se potrivește cu niciunul, sau se potrivește cu două, nu e ignorat: e raportat.
DNF_ROLES = {
    "main": lambda f: "-C" not in f and "--installed" not in f,
    "control": lambda f: "--installed" in f,
    "advisory": lambda f: "-C" in f and "--installed" not in f and "cves" not in f,
}


def dnf_roles_of(flags: set[str]) -> list[str]:
    """Rolurile ale căror predicate se potrivesc cu aceste jetoane din argv (exact
    unul, când apelul e sănătos)."""
    return [role for role, matches in DNF_ROLES.items() if matches(flags)]


def _findings(source: str) -> list[tuple[str | None, str]]:
    """Toate motivele, fiecare cu rolul la care se referă (`None` = nu se poate
    atribui unui rol: argv ilizibil, apel fără rol sau cu două roluri, listă dnf
    care nu ajunge la `_run`)."""
    tree = ast.parse(source)
    found: list[tuple[str | None, str]] = []
    by_role: dict[str, list[ast.Call]] = {role: [] for role in DNF_CEILINGS}
    claimed: set[int] = set()

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_run"):
            continue
        argv = node.args[0] if node.args else next(
            (k.value for k in node.keywords if k.arg == "argv"), None)
        if not (isinstance(argv, ast.List) and argv.elts
                and isinstance(argv.elts[0], ast.Constant)):
            # Nu se poate citi ce comandă e: „necunoscut" nu e „în regulă".
            found.append((None,
                f"linia {node.lineno}: `_run` primește un argv care nu e o listă "
                "literală cu comanda pe primul loc, deci nu pot spune dacă e dnf"))
            continue
        if argv.elts[0].value != "dnf":
            continue
        claimed.add(id(argv))
        flags = {e.value for e in argv.elts
                 if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        roles = dnf_roles_of(flags)
        if len(roles) != 1:
            found.append((None,
                f"linia {node.lineno}: apelul dnf {sorted(flags - {'dnf'})} nu are un "
                f"rol și numai unul (potrivit cu: {roles or 'niciunul'}) — un apel nou "
                "are nevoie de propriul plafon, propria constantă și propriul rol aici"))
            continue
        by_role[roles[0]].append(node)

    # O listă `["dnf", ...]` care nu ajunge la `_run` scapă de tot ce e mai sus.
    for node in ast.walk(tree):
        if (isinstance(node, ast.List) and node.elts
                and isinstance(node.elts[0], ast.Constant)
                and node.elts[0].value == "dnf" and id(node) not in claimed):
            found.append((None,
                f"linia {node.lineno}: un argv dnf care nu e primul argument al "
                "lui `_run`: plafonul lui nu poate fi verificat"))

    for role, constant in DNF_CEILINGS.items():
        calls = by_role[role]
        if len(calls) != 1:
            found.append((role,
                f"rolul `{role}` are {len(calls)} apeluri dnf, nu unul "
                f"(linii: {[c.lineno for c in calls]})"))
        for call in calls:
            ceiling = next((k.value for k in call.keywords if k.arg == "timeout"), None)
            if not (isinstance(ceiling, ast.Name) and ceiling.id == constant):
                cerut = ast.unparse(ceiling) if ceiling is not None else "niciun timeout"
                found.append((role,
                    f"linia {call.lineno}: apelul dnf `{role}` trebuie să ceară "
                    f"`timeout={constant}`, dar cere: {cerut}"))
    return found


def dnf_ceiling_problems(source: str, role: str | None = None) -> list[str]:
    """Fiecare motiv pentru care apelurile dnf din `source` nu poartă fiecare plafonul
    lui. Listă goală = fiecare dintre cele trei roluri e apelat o singură dată, cu
    exact constanta din `DNF_CEILINGS`.

    Cu `role=`, doar motivele acelui rol PLUS cele care nu se pot atribui niciunui
    rol: un test despre plafonul interogării de aviz nu pică fiindcă a pierdut altul
    al controlului (asta o spune celălalt test, pe numele controlului), dar pică
    dacă un apel nou sau ilizibil face imposibil de spus care e al lui."""
    if role is not None and role not in DNF_CEILINGS:
        raise KeyError(f"rol necunoscut: {role!r} (roluri: {sorted(DNF_CEILINGS)})")
    return [text for who, text in _findings(source) if role is None or who in (None, role)]
