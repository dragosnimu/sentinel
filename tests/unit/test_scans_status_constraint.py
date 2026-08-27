"""`scans.status` nu mai poate purta o valoare pe care nimeni n-o citește onest.

Eșecul, citit din cod pe 26 august 2026 — nu văzut pe gazdă, unde sunt 0 rânduri
`skipped`: `check_last_scan` tratează orice status care nu e `running`, `failed`
sau `timeout` ca pe o rulare încheiată, deci un rând cu `status = 'skipped'` ar fi
ieșit «ok | ultima rulare încheiată acum 1h, 0 constatări». „0 constatări" despre
o scanare care nu a rulat e un panou verde pus peste o măsurătoare care nu s-a
făcut niciodată — chiar forma de minciună pe care verificarea aia există ca s-o
prevină. E o cale deschisă, nu o pană trăită; se spune așa fiindcă aici
docstring-ul e evidența.

Nimic din cod nu scria valoarea. Era o capcană armată pentru primul care avea s-o
scrie, iar decizia operatorului a fost s-o facă NEREPREZENTABILĂ, nu s-o trateze:
gestionată, corectitudinea ar depinde de fiecare cititor viitor; scoasă din
constrângere, baza refuză.

Testele de aici păzesc trei lucruri: că starea chiar a ieșit din schemă, că
migrația refuză în loc să rescrie istoric, și că niciun apel din cod nu scrie un
status pe care baza l-ar respinge — adică nu se repară o parte și se sparge alta.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "sentinel" / "db" / "migrations"

_ADD_CONSTRAINT = re.compile(
    r"ADD\s+CONSTRAINT\s+scans_status_check\s+CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)\s*\)",
    re.I | re.S)
_LITERAL = re.compile(r"'([a-z_]+)'")


def _migrations_in_order() -> list[tuple[int, Path]]:
    found = [(int(re.match(r"^(\d+)_", f.name).group(1)), f)
             for f in MIGRATIONS.glob("*.sql")]
    assert found, f"nicio migrație găsită în {MIGRATIONS}"
    return sorted(found)


def _effective_scans_statuses() -> tuple[int, set[str]]:
    """Ce valori acceptă `scans.status` după TOATE migrațiile, și din care vine.

    Se citește ultima constrângere numită `scans_status_check` adăugată explicit.
    Constrângerea originală din 0003 e anonimă (Postgres o botează după
    convenția `<tabelă>_<coloană>_check`), deci nu apare aici — și tocmai de-aia
    testul de mai jos verifică separat că ea chiar conținea `skipped`: altfel
    testul ar putea trece pe un depozit unde n-a fost niciodată nimic de scos.
    """
    ultima: tuple[int, set[str]] | None = None
    for version, path in _migrations_in_order():
        m = _ADD_CONSTRAINT.search(path.read_text(encoding="utf-8"))
        if m:
            ultima = (version, set(_LITERAL.findall(m.group(1))))
    assert ultima is not None, (
        "nicio migrație nu adaugă `scans_status_check` cu nume explicit, deci "
        "constrângerea efectivă e tot cea anonimă din 0003")
    return ultima


def test_the_scans_status_constraint_no_longer_admits_skipped() -> None:
    """Starea care mințea nu mai poate ajunge în tabelă.

    Eșecul pe care îl previne: cât timp `'skipped'` e o valoare legală,
    următoarea bucată de cod care o scrie — un scaner condiționat, o rulare
    întreruptă din configurație — produce imediat «ultima rulare încheiată acum
    1h, 0 constatări» în `/selfcheck` și în panou, fără ca nimeni să atingă
    verificarea. Baza e singurul loc unde asta se oprește o dată pentru tot.
    """
    version, statuses = _effective_scans_statuses()
    assert "skipped" not in statuses, (
        f"constrângerea efectivă (din migrația {version:04d}) încă acceptă "
        f"`skipped`: {sorted(statuses)}")
    assert statuses == {"running", "completed", "failed", "timeout"}, (
        f"lista de statusuri s-a schimbat altfel decât se aștepta: "
        f"{sorted(statuses)}")


def test_the_original_constraint_really_did_admit_skipped() -> None:
    """Fără asta, testul de deasupra ar putea trece degeaba.

    Eșecul pe care îl previne: dacă `0003` n-ar fi conținut niciodată `skipped`,
    testul de deasupra ar fi verde pe un depozit în care nu s-a reparat nimic —
    o aserțiune care nu poate pica nu păzește nimic. Aici se arată că valoarea
    chiar era acolo, deci că migrația nouă are ce scoate.

    `0003` e imuabilă (runner-ul refuză o migrație aplicată al cărei conținut
    s-a schimbat), deci propoziția asta rămâne adevărată prin construcție.
    """
    text = (MIGRATIONS / "0003_vuln.sql").read_text(encoding="utf-8")
    bloc = text[text.index("CREATE TABLE scans"):]
    bloc = bloc[:bloc.index("\n);")]
    m = re.search(r"CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)\s*\)", bloc, re.I | re.S)
    assert m, f"nu am găsit constrângerea de status în CREATE TABLE scans:\n{bloc}"
    assert "skipped" in set(_LITERAL.findall(m.group(1)))


def test_the_migration_refuses_the_rows_instead_of_rewriting_them() -> None:
    """Rândurile existente nu se convertesc tăcut — și nici nu se șterg.

    Eșecul pe care îl previne: `UPDATE scans SET status='completed' WHERE status
    ='skipped'` ar fi trecut migrația fără o vorbă și ar fi REscris istoric — o
    rulare care n-a măsurat nimic ar fi devenit, în date, una care a măsurat și
    n-a găsit nimic. Adică exact afirmația falsă din care a pornit toată treaba,
    doar că împietrită în tabelă în loc să fie produsă la citire. Un `DELETE` ar
    fi pierdut singura urmă că cineva scrie valoarea aia.

    Pe gazda operatorului sunt 0 astfel de rânduri, deci refuzul e operație nulă.
    Dacă se declanșează pe altă instanță, aia e informație, nu obstacol — și
    atunci mesajul trebuie să-i spună operatorului ce are de făcut.

    A doua gaură, astupată aici: decuparea literalilor de șir e OARBĂ la SQL
    dinamic. Un `DO $$ BEGIN EXECUTE 'UPDATE scans SET status = ...'; END $$;`
    strecurat înaintea lui `ALTER TABLE` e, pentru regexul de mai jos, un șir
    care dispare cu totul — conversia tăcută pe care întreaga migrație există
    s-o refuze trecea paza fără o vorbă, cu suita verde.
    """
    sql = (MIGRATIONS / "0029_scans_no_skipped.sql").read_text(encoding="utf-8")
    # Comentariile explică tocmai ce NU face migrația; scrieri se caută doar în cod.
    cod = "\n".join(l for l in sql.splitlines() if not l.lstrip().startswith("--"))

    # Interdicția pe SQL dinamic se pune pe `cod`, ÎNAINTE de decuparea de mai
    # jos — altfel tocmai scrierea ascunsă într-un literal ar fi cea decupată.
    # Migrația n-are nevoie de `EXECUTE` ca să facă ce spune (numără, refuză,
    # rescrie constrângerea, probează efectul), deci interdicția totală e
    # gratuită și nu cere nicio judecată despre ce e înăuntrul șirului.
    assert not re.search(r"\bEXECUTE\b", cod, re.I), (
        "migrația conține SQL dinamic; orice scriere de acolo e invizibilă "
        "pentru aserțiunile de mai jos, care caută în codul fără literali de șir")

    # …iar mesajul de refuz îi ARATĂ operatorului un `UPDATE` pe care să-l ruleze
    # el, cu ochii pe rând. Ăla e text, nu instrucțiune. Căutarea de scrieri se
    # face pe cod fără literali de șir, altfel sfatul ar fi confundat cu fapta.
    executabil = re.sub(r"'(?:[^']|'')*'", "''", cod)

    assert not re.search(r"UPDATE\s+scans\s+SET", executabil, re.I), (
        "migrația scrie în `scans` — o conversie tăcută rescrie istoric")
    assert not re.search(r"DELETE\s+FROM\s+scans", executabil, re.I), (
        "migrația șterge din `scans` — se pierde urma scriitorului necunoscut")

    assert re.search(r"count\(\*\)\s+INTO\s+n\s+FROM\s+scans\s+WHERE\s+status\s*=\s*'skipped'",
                     cod, re.I), (
        "migrația nu numără rândurile `skipped`, deci n-are de unde ști dacă "
        "există vreunul de care să se împiedice")
    assert re.search(r"IF\s+n\s*>\s*0\s+THEN", cod, re.I), cod
    assert "RAISE EXCEPTION" in cod, (
        "migrația nu se oprește; ar trece peste rânduri pe care nu le înțelege")
    # Refuzul trebuie să-i spună ce să facă, nu doar că refuză.
    assert "HINT" in cod and "SELECT id, scanner" in cod, (
        "mesajul de refuz nu-i arată operatorului cum să vadă rândurile")


def test_the_migration_proves_the_constraint_bites_instead_of_assuming_it() -> None:
    """`ALTER TABLE` care întoarce succes nu e dovadă că baza respinge valoarea.

    Eșecul pe care îl previne, în forma pe care o are tot depozitul ăsta:
    `DROP CONSTRAINT IF EXISTS scans_status_check` nu întoarce eroare când nu
    găsește nimic. Dacă în 0003 constrângerea ar purta alt nume decât cel dat de
    convenția Postgres, dropul n-ar șterge nimic, s-ar adăuga una nouă lângă cea
    veche, migrația ar raporta succes — și abia peste luni s-ar afla că nu
    valoarea a fost scoasă, ci doar că s-a mai adăugat un rând în catalog.

    Ce verifică testul ăsta: că migrația își pune la încercare propriul efect,
    adică încearcă să insereze `skipped` și se rupe dacă baza îl acceptă. Ce NU
    verifică: că blocul chiar rulează așa — asta se vede numai pe un Postgres.
    """
    sql = (MIGRATIONS / "0029_scans_no_skipped.sql").read_text(encoding="utf-8")
    cod = "\n".join(l for l in sql.splitlines() if not l.lstrip().startswith("--"))

    proba = re.search(r"INSERT\s+INTO\s+scans\s*\([^)]*status[^)]*\)\s*VALUES\s*\([^)]*'skipped'[^)]*\)",
                      cod, re.I | re.S)
    assert proba, (
        "migrația nu încearcă niciodată să insereze `skipped`, deci raportează "
        "intenția (am rescris constrângerea), nu efectul (baza o respinge)")
    dupa = cod[proba.end():]
    assert "RAISE EXCEPTION" in dupa, (
        "proba se inserează dar nimic nu se întâmplă dacă REUȘEȘTE — o probă "
        "care nu poate pica nu dovedește nimic")
    assert "check_violation" in dupa, (
        "nu se prinde respingerea așteptată, deci calea fericită ar rupe migrația")


# ---------------------------------------------------------------------------
# Codul și schema trebuie să spună acelaşi lucru
# ---------------------------------------------------------------------------
def _finish_scan_statuses() -> list[tuple[str, str]]:
    """Fiecare `status=` literal dat lui `finish_scan`, cu fișierul din care vine."""
    gasite: list[tuple[str, str]] = []
    for pachet in ("sentinel", "executor"):
        for path in (ROOT / pachet).rglob("*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError as exc:  # pragma: no cover - ar pica oricum la import
                pytest.fail(f"{path}: {exc}")
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                nume = fn.attr if isinstance(fn, ast.Attribute) else (
                    fn.id if isinstance(fn, ast.Name) else None)
                if nume != "finish_scan":
                    continue
                for kw in node.keywords:
                    if kw.arg == "status" and isinstance(kw.value, ast.Constant) \
                            and isinstance(kw.value.value, str):
                        gasite.append((str(path.relative_to(ROOT)), kw.value.value))
    return gasite


def test_no_code_path_writes_a_status_the_constraint_would_reject() -> None:
    """Ce scrie codul trebuie să încapă în ce acceptă baza.

    Eșecul pe care îl previne: strâmtând constrângerea, un apel rămas cu o
    valoare scoasă ar începe să arunce `CheckViolationError` la finalul fiecărei
    scanări. Rândul ar rămâne `running` pentru totdeauna — adică fix defectul
    celălalt din runda asta, produs de reparația acestuia.

    Aserțiunea pe lista NEGOALĂ e la fel de importantă ca cea pe conținut: o
    căutare care nu găsește niciun apel ar trece liniștită pentru totdeauna, și
    exact așa au trecut aici teste care nu verificau nimic.
    """
    _, permise = _effective_scans_statuses()
    gasite = _finish_scan_statuses()
    assert gasite, (
        "niciun apel `finish_scan(status=...)` găsit prin AST — testul nu "
        "verifică nimic; s-a mutat funcția sau i s-a schimbat numele?")

    gresite = [(f, s) for f, s in gasite if s not in permise]
    assert not gresite, (
        f"apeluri care scriu un status respins de `scans_status_check` "
        f"({sorted(permise)}): {gresite}")
