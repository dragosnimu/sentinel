"""Scanerul de pachete și unitatea lui trebuie să vorbească despre ACELAȘI cache.

Eșecul pe care îl previne, măsurat pe gazda reală pe 21 august 2026:
`dnf updateinfo list cves` rulează în 7 secunde ca root — care folosește cache-ul
sistemului din `/var/cache/dnf` — și în **82** ca utilizatorul `sentinel`, care
nu-l poate citi și reconstruiește toate metadatele la fiecare rulare. Plafonul
scanerului era 120 de secunde, iar rulările reale luau între 82 și 120: o monedă
aruncată în fiecare noapte. A picat de patru ori în două săptămâni, iar de
fiecare dată lista de vulnerabilități a rămas înghețată fără ca nimeni să afle.

Cu un cache propriu, scris o dată și refolosit: 2,4 secunde.

Ce leagă testul ăsta: calea din cod și cea creată de systemd. Despărțite, una
s-ar muta la o refactorizare și cealaltă ar scrie în continuare într-un director
pe care nu-l mai creează nimeni — iar simptomul ar fi fix cel de mai sus, întors,
fără nimic care să-l explice.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from sentinel.scan import os_packages
from tests.unit._dnf_ceilings import (
    DNF_CEILINGS, DNF_ROLES, dnf_ceiling_problems, dnf_roles_of)

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "deploy" / "systemd" / "sentinel-scan.service"


def _unit() -> str:
    return UNIT.read_text(encoding="utf-8")


def test_the_unit_creates_the_directory_the_scanner_writes_to() -> None:
    """`CacheDirectory=X` face `/var/cache/X`. Trebuie să fie exact `CACHE_DIR`.

    Citite TOATE liniile, nu prima: unitatea are mai multe `CacheDirectory=` de
    când trivy și-a primit cache-ul lui, iar o aserțiune pe prima potrivire ar
    fi devenit un test despre ordinea liniilor din fișier. Reordonate mâine de
    cineva care aranjează secțiunea, ar fi picat fără ca nimic să se strice —
    sau, mai rău, ar fi trecut comparând calea lui dnf cu a altui scaner.
    """
    valori = re.findall(r"^CacheDirectory=(\S+)$", _unit(), re.M)
    assert valori, (
        "unitatea nu declară `CacheDirectory=`, deci dnf ar scrie într-un "
        "director pe care nimeni nu-l creează — și fiecare scanare ar "
        "reconstrui metadatele, ca înainte de reparație")
    create = {f"/var/cache/{v}" for v in valori}
    assert os_packages.CACHE_DIR in create, (
        f"unitatea creează {sorted(create)}, iar scanerul de pachete scrie în "
        f"{os_packages.CACHE_DIR}")


def test_the_scanner_actually_passes_the_cache_dir_to_dnf() -> None:
    """Constanta declarată și nefolosită e o reparație pe hârtie.

    Verificat pe SURSĂ, nu pe constantă: un `CACHE_DIR` corect pe care nu-l
    primește dnf lasă comportamentul neschimbat, iar testul de mai sus ar trece
    în continuare.
    """
    source = (ROOT / "sentinel" / "scan" / "os_packages.py").read_text(encoding="utf-8")
    assert "--setopt=cachedir=" in source, (
        "dnf nu primește niciun `cachedir`, deci folosește implicitul — cel pe "
        "care utilizatorul neprivilegiat nu-l poate scrie")
    assert "{CACHE_DIR}" in source, (
        "calea e scrisă de mână în argument, deci se poate despărți de constantă")


def test_the_directory_survives_between_runs() -> None:
    """`RuntimeDirectory=` l-ar șterge la oprire și ar readuce exact problema.

    Un cache care dispare după fiecare rulare nu e un cache — e o cheltuială.
    """
    text = _unit()
    assert not re.search(r"^RuntimeDirectory=.*dnf", text, re.M), (
        "cache-ul e declarat ca director de rulare, deci se șterge la oprirea "
        "serviciului și fiecare scanare o ia de la capăt")


def test_the_timeout_has_room_for_the_worst_case_that_remains() -> None:
    """Cache-ul rezolvă cazul obișnuit; plafonul trebuie să acopere primul.

    Prima rulare după ce cache-ul e șters a fost măsurată la 87 de secunde. Un
    plafon apropiat de ea readuce moneda aruncată, doar mai rar — iar mai rar e
    mai rău: o pană care apare o dată la două luni nu e diagnosticată, e uitată.
    """
    assert os_packages.TIMEOUT_S >= 180, (
        f"plafonul e {os_packages.TIMEOUT_S}s, iar prima rulare fără cache a fost "
        f"măsurată la 87s — marginea trebuie să fie peste dublu")


def test_run_has_no_default_timeout_at_all() -> None:
    """Un implicit e felul în care plafonul lui dnf ajunge pe altă comandă.

    Testul de aici cerea până pe 28 august 2026 ca implicitul lui `_run` să fie
    egal cu `TIMEOUT_S`. De când modulul are două backend-uri — dnf pe rhel,
    apt pe debian —, un implicit e mai rău decât unul rămas în urmă: e plafonul
    unui backend moștenit tăcut de celălalt, adică exact defectul pe care
    `trivy_fs._run` l-a scos ieri, unde bugetul unei rulări devenise unul per
    apel. Fiecare apel își spune plafonul.
    """
    import inspect

    param = inspect.signature(os_packages._run).parameters["timeout"]
    assert param.default is inspect.Parameter.empty, (
        f"`_run` are implicitul {param.default!r}: un al doilea backend adăugat "
        f"mâine îl moștenește fără să scrie nicăieri cât așteaptă")


def test_every_dnf_call_asks_for_its_own_declared_timeout() -> None:
    """Fiecare apel dnf poartă plafonul lui declarat, oriunde ar sta în fișier.

    Eșecul pe care îl previne: un `timeout=120` scris de mână la un apel dnf, cu
    constanta declarată alături spunând altceva. E moneda aruncată din 21 august 2026
    (o rulare reală lua 82-120 s față de un plafon de 120 s, scanarea a picat de
    patru ori în două săptămâni, iar lista de vulnerabilități a rămas înghețată fără
    ca cineva să afle), iar acum sunt trei apeluri dnf, deci trei locuri pentru ea.
    Forma veche a testului citea „primul apel dnf din fișier", ceea ce făcea ordinea
    funcțiilor importantă pentru un test fără legătură.

    Verificat pe SURSĂ, nu pe constante: `_run` n-are implicit, deci constantele nu
    spun ce număr trimite un apel anume. Citirea o face `_dnf_ceilings.py`, aceeași
    pe care o folosește și `test_scan_dnf_advisories.py`.
    """
    source = (ROOT / "sentinel" / "scan" / "os_packages.py").read_text(encoding="utf-8")
    problems = dnf_ceiling_problems(source)

    assert not problems, "\n".join(problems)


def test_the_shared_reader_depends_on_nothing_that_could_be_left_out_of_a_commit() -> None:
    """`_dnf_ceilings.py` e importat de trei fișiere de teste și trebuie comis odată cu
    ele. Dacă ar importa la rândul lui altceva necomis (un alt ajutor, un modul nou din
    `sentinel/`, o fixtură citită la import), ar exista un al doilea fișier de uitat, iar
    o clonă proaspătă ar pica la COLECTARE — trei fișiere de teste dispărute din rulare
    cu o eroare de import, nu un test roșu care numește ceva. De aici: doar biblioteca
    standard, și la nivelul modulului doar importuri, constante și definiții, fără
    apeluri (nicio citire de fișier la import).

    Ce NU poate afirma testul ăsta: că fișierul e comis. Fără git în clona de test ar fi
    o presupunere, iar înainte de comit ar fi roșu prin construcție; asta o dovedește
    rularea suitei într-o clonă curată."""
    import sys

    tree = ast.parse((ROOT / "tests" / "unit" / "_dnf_ceilings.py").read_text(encoding="utf-8"))

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"import relativ la linia {node.lineno}: depinde de vecini"
            imported.add((node.module or "").split(".")[0])
    assert imported, "nu am găsit niciun import: testul ar judeca un fișier pe care nu-l citește"
    outside_stdlib = sorted(m for m in imported if m not in sys.stdlib_module_names)
    assert not outside_stdlib, (
        f"`_dnf_ceilings.py` importă în afara bibliotecii standard: {outside_stdlib}")

    # Docstring-ul modulului e primul `Expr`; orice alt `Expr` e un apel la import.
    # `AnnAssign` si `ClassDef` sunt aici fiindca verificatorul a aratat ca lipsa
    # lor da fals pozitiv: `X: dict[str, str] = {...}` ar fi acuzata ca „ruleaza
    # cod la import", ceea ce nu e adevarat, iar mesajul l-ar trimite pe
    # urmatorul dupa o problema inexistenta.
    allowed = (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign,
               ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    for i, node in enumerate(tree.body):
        is_docstring = i == 0 and isinstance(node, ast.Expr) and isinstance(
            node.value, ast.Constant) and isinstance(node.value.value, str)
        assert is_docstring or isinstance(node, allowed), (
            f"linia {node.lineno}: `{type(node).__name__}` la nivelul modulului rulează "
            "cod la import")
        if isinstance(node, ast.Assign):
            assert not any(isinstance(n, ast.Call) for n in ast.walk(node.value)), (
                f"linia {node.lineno}: o atribuire la nivelul modulului face un apel la import")


def test_a_role_with_no_dnf_call_at_all_is_reported_not_passed_over():
    """Un rol ramas fara niciun apel — cineva rescrie `dnf` in `dnf5`, sau sterge
    interogarea — trebuie numit, nu trecut cu vederea.

    Ce se strica daca pica: ramura `len(calls) != 1` are doua jumatati, iar
    numai cea cu DOUA apeluri era exercitata. Verificatorul a aratat ca o
    rescriere in `dnf5` scoate apelul din orice rol, si ca `!= 1` slabit la
    `> 1` supravietuia suitei intregi. Atunci plafonul rolului aceluia n-ar mai
    fi pazit de nimic, in tacere.
    """
    fara_control = "".join(t for r, t in _THREE_CALLS.items() if r != "control")
    problems = dnf_ceiling_problems(fara_control)

    assert any("`control` are 0 apeluri" in m for m in problems), (
        f"un rol fara niciun apel dnf a trecut nevazut: {problems}")
    assert not any("`main`" in m or "`advisory`" in m for m in problems), problems


_THREE_CALLS = {
    "main": (
        "async def a():\n"
        "    return await _run([\n"
        "        \"dnf\", \"-q\", \"updateinfo\", \"list\", \"cves\", \"--security\"],\n"
        "        timeout=TIMEOUT_S)\n"),
    "control": (
        "async def b():\n"
        "    return await _run([\"dnf\", \"-C\", \"updateinfo\", \"list\", \"--security\",\n"
        "                       \"--installed\"], timeout=CONTROL_TIMEOUT_S)\n"),
    "advisory": (
        "async def c():\n"
        "    return await _run(\n"
        "        [\"dnf\", \"-C\", \"updateinfo\", \"list\", \"--security\"],\n"
        "        timeout=ADVISORY_TIMEOUT_S)\n"),
}


@pytest.mark.parametrize("order", [
    ("main", "control", "advisory"), ("advisory", "control", "main"),
    ("control", "main", "advisory"), ("advisory", "main", "control")])
def test_the_ceiling_check_does_not_depend_on_function_order(order) -> None:
    """Aceleași trei apeluri, în orice ordine, trec: nimeni nu mai trebuie să țină
    `_scan_dnf` deasupra controlului doar ca testele să citească apelul potrivit.
    Jumătatea pozitivă: un verificator care ar întoarce mereu o problemă ar „trece"
    și testele negative de mai jos."""
    assert dnf_ceiling_problems("".join(_THREE_CALLS[r] for r in order)) == []


def test_a_fourth_dnf_call_without_its_own_ceiling_is_reported_not_ignored() -> None:
    """Un apel dnf nou (să zicem o reinterogare CVE din cache) trebuie să pice aici și
    să-și numească linia, nu să fie sărit fiindcă cele trei cunoscute arată în
    continuare bine: un apel negăsit în listă e exact cel care ar moșteni plafonul
    altcuiva."""
    fourth = ("async def d():\n"
              "    return await _run([\"dnf\", \"-C\", \"updateinfo\", \"list\", \"cves\",\n"
              "                       \"--security\"], timeout=TIMEOUT_S)\n")
    problems = dnf_ceiling_problems("".join(_THREE_CALLS.values()) + fourth)
    # `_run(` e pe a doua linie a lui `d`, după cele trei funcții deja scrise.
    line = sum(t.count("\n") for t in _THREE_CALLS.values()) + 2

    assert len(problems) == 1 and f"linia {line}:" in problems[0], problems
    fifth = ("async def e():\n"
             "    return await _run([\"dnf\", \"makecache\"], timeout=TIMEOUT_S)\n")
    problems = dnf_ceiling_problems("".join(_THREE_CALLS.values()) + fifth)
    assert any("rolul `main` are 2 apeluri" in p for p in problems), problems


@pytest.mark.parametrize("role", list(DNF_CEILINGS))
def test_a_dnf_call_without_its_ceiling_is_reported_by_role(role) -> None:
    """Scoți plafonul unui apel, sau îl înlocuiești cu un literal: raportul numește
    ACEL apel, ca operatorul să nu compare trei apeluri aproape identice ca să afle
    care și-a pierdut plafonul."""
    constant = DNF_CEILINGS[role]
    calls = dict(_THREE_CALLS)
    calls[role] = calls[role].replace(f"timeout={constant}", "timeout=120")
    assert calls[role] != _THREE_CALLS[role]
    problems = dnf_ceiling_problems("".join(calls.values()))
    assert len(problems) == 1 and f"`{role}`" in problems[0], problems

    calls[role] = _THREE_CALLS[role].replace(f", timeout={constant}", "").replace(
        f",\n        timeout={constant}", "")
    assert "timeout" not in calls[role]
    problems = dnf_ceiling_problems("".join(calls.values()))
    assert len(problems) == 1 and "niciun timeout" in problems[0], problems

    # Alt plafon declarat, dar al altui apel: tot un plafon care minte.
    other = next(c for c in DNF_CEILINGS.values() if c != constant)
    calls[role] = _THREE_CALLS[role].replace(f"timeout={constant}", f"timeout={other}")
    problems = dnf_ceiling_problems("".join(calls.values()))
    assert len(problems) == 1 and f"`{role}`" in problems[0], problems


def test_asking_for_one_role_hides_the_other_roles_problems_but_never_an_unattributable_one(
) -> None:
    """`test_scan_dnf_advisories.py` întreabă doar de rolul `advisory`. Un plafon
    pierdut de CONTROL nu are voie să-l facă să pice (ar arăta operatorului testul
    greșit; îl numește celălalt, pe rolul lui) — dar un apel nou sau ilizibil, care
    face imposibil de spus care apel e al interogării de aviz, trebuie să-l facă să
    pice pe orice rol, altfel filtrul ar fi o gaură prin care trece un apel dnf
    necunoscut. Și un rol scris greșit e o eroare, nu „nicio problemă"."""
    fara_plafon = dict(_THREE_CALLS)
    fara_plafon["control"] = _THREE_CALLS["control"].replace(
        "timeout=CONTROL_TIMEOUT_S", "timeout=120")
    assert fara_plafon["control"] != _THREE_CALLS["control"]
    sursa = "".join(fara_plafon.values())

    assert dnf_ceiling_problems(sursa, role="advisory") == []
    assert len(dnf_ceiling_problems(sursa, role="control")) == 1
    assert len(dnf_ceiling_problems(sursa)) == 1

    ilizibil = ("".join(_THREE_CALLS.values())
                + "async def f(cmd):\n    return await _run(cmd, timeout=TIMEOUT_S)\n")
    for role in DNF_CEILINGS:
        assert any("nu pot spune" in p for p in dnf_ceiling_problems(ilizibil, role=role))

    with pytest.raises(KeyError):
        dnf_ceiling_problems(sursa, role="advisories")


@pytest.mark.parametrize("flags, role", [
    ({"dnf", "-q", "cves", "--security"}, ["main"]),
    ({"dnf", "-q", "--security"}, ["main"]),           # o interogare de aviz fără `-C`
    ({"dnf", "-C", "-q", "--security", "--installed"}, ["control"]),
    ({"dnf", "-q", "--security", "--installed"}, ["control"]),
    ({"dnf", "-C", "-q", "--security"}, ["advisory"]),
    ({"dnf", "-C", "-q", "cves", "--security"}, []),   # `-C` + `cves`: niciun rol
])
def test_the_roles_are_told_apart_by_their_own_tokens(flags, role) -> None:
    """Cele trei roluri nu se pot confunda fiindcă se despart după două steaguri, `-C`
    și `--installed`, iar `cves` exclude doar rolul de aviz: fără `-C` e interogarea
    principală; `--installed` e controlul; `-C` fără `--installed` și fără `cves` e
    interogarea de aviz. Un apel care nu se potrivește cu niciunul (reinterogare CVE
    din cache) n-are rol, iar un apel fără rol e raportat, niciodată presupus a fi
    unul dintre cele trei."""
    assert dnf_roles_of(flags) == role


def test_a_call_that_fits_two_roles_is_reported_not_resolved_silently(monkeypatch) -> None:
    """Dacă cineva lărgește un predicat până când două roluri revendică același argv,
    alegerea primului ar ascunde față de ce plafon a fost verificat apelul."""
    monkeypatch.setitem(DNF_ROLES, "advisory", lambda f: True)
    problems = dnf_ceiling_problems("".join(_THREE_CALLS.values()))

    assert any("potrivit cu: ['main', 'advisory']" in p for p in problems), problems


def test_a_dnf_argv_that_is_not_a_literal_is_reported_as_unreadable() -> None:
    """`_run(cmd, timeout=...)` cu `cmd` construit în altă parte nu se poate deosebi
    de un apel dnf, iar „nu pot spune" nu are voie să se citească „în regulă"."""
    problems = dnf_ceiling_problems(
        "".join(_THREE_CALLS.values())
        + "async def f(cmd):\n    return await _run(cmd, timeout=TIMEOUT_S)\n")
    assert any("nu pot spune" in p for p in problems), problems


def test_a_dnf_argv_that_never_reaches_run_is_reported() -> None:
    """O listă `["dnf", ...]` dată la altceva decât `_run` (un ajutor, un apel direct
    la subprocess) scapă de toate verificările de plafon de mai sus, deci simpla ei
    existență e raportată, nu presupusă nevinovată."""
    problems = dnf_ceiling_problems(
        "".join(_THREE_CALLS.values())
        + "async def g():\n    return await other([\"dnf\", \"-q\"])\n")
    assert len(problems) == 1 and "nu e primul argument" in problems[0], problems


@pytest.mark.parametrize("cale", ["/var/cache/dnf", "/tmp", "/var/tmp"])
def test_the_cache_is_not_somewhere_shared_or_volatile(cale: str) -> None:
    """Nu cache-ul lui root, și nu un director temporar.

    `/var/cache/dnf` aparține lui root: scanerul n-are voie acolo, iar dacă ar
    avea, ar putea strica metadatele pe care se bazează `dnf update`. `/tmp` se
    golește, deci fiecare rulare ar fi prima.
    """
    assert os_packages.CACHE_DIR != cale
    assert not os_packages.CACHE_DIR.startswith(cale + "/")
