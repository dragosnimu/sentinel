"""Un parametru care intră într-o aritmetică de timp trebuie să poarte cast.

## De ce există fișierul ăsta

Aceeași clasă de defect a trecut de suita verde de **trei ori într-o zi**, pe
24 august 2026, și de fiecare dată a căzut abia în producție:

  1. `(updated_at, bucket) > ($1::timestamptz, $2::text)` — Postgres a refuzat la
     compilare: «operator does not exist: timestamp with time zone > text».
     Fluxul de agregate a tăcut trei runde;
  2. `$2::timestamptz` primind valoarea din `collector_cursors.cursor`, care e
     stocată ca text — asyncpg a refuzat la legare: «invalid input for query
     argument $2 … expected a datetime»;
  3. `closed_at >= $2 - interval '1 day'` — fără cast, Postgres deduce `interval`
     pentru parametru și instrucțiunea devine `timestamptz >= interval`.
     **Ingestia întreagă a picat**, nu doar funcția nouă: fiecare rundă a
     colectorului a eșuat până când s-a citit jurnalul.

Cauza comună nu e neatenția, e o gaură în cum se probează SQL-ul aici: dublele de
test primesc instrucțiunea ca TEXT și valorile ca obiecte Python. Nimic din ele
nu leagă tipuri, deci nimic nu poate observa că baza n-ar accepta perechea. Un
dublu nu poate prinde asta niciodată — deci se caută în sursă.

## Ce caută

`$N` folosit direct într-o adunare sau scădere cu `interval`. Postgres rezolvă
tipul unui parametru din context, iar în `$N - interval '1 day'` contextul spune
`interval`. Cu un cast — `$N::timestamptz - interval '1 day'` — contextul e
neambiguu.

Nu prinde toate greșelile de tip. Prinde exact forma care a doborât ingestia, iar
o gardă care prinde o formă cunoscută e mai bună decât una care le promite pe
toate și nu ține niciuna.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: Fișierele în care se caută. SQL-ul trăiește în Python, nu în `.sql`: fișierele
#: de migrație n-au parametri legați, deci n-au cum să aibă defectul.
SEARCHED = ("sentinel", "executor")

#: `$1 - interval`, `$2 + interval` — fără niciun cast între ele.
#:
#: `[^:]` după numărul parametrului e ce lasă `$1::timestamptz - interval` să
#: treacă: acolo tipul e spus, deci contextul nu mai trebuie ghicit.
UNTYPED = re.compile(r"\$\d+\s*[-+]\s*(?:make_)?interval", re.IGNORECASE)

#: Aceeași formă, dar cu tipul spus. Se caută separat ca să se poată dovedi că
#: tiparul de mai sus chiar deosebește cele două — un tipar care ar potrivi și
#: forma corectă ar fi la fel de inutil ca unul care nu potrivește nimic.
TYPED = re.compile(r"\$\d+::\w+\s*[-+]\s*(?:make_)?interval", re.IGNORECASE)


def _sources() -> list[Path]:
    out: list[Path] = []
    for top in SEARCHED:
        out.extend(p for p in (ROOT / top).rglob("*.py")
                   if "__pycache__" not in p.parts)
    return out


#: Ce FIXEAZĂ tipul unui parametru altundeva în aceeași instrucțiune.
#:
#: `ts >= $3` îi spune lui Postgres că `$3` e de tipul lui `ts`, iar de acolo
#: `$3 + interval '1 minute'` e neambiguu. De-asta garda nu se uită la o singură
#: linie: forma `WHERE ts >= $3 AND ts < $3 + interval '1 minute'` există în
#: `detect/rules.py` de luni de zile și funcționează.
#:
#: O gardă care țipă la cod care merge e o gardă pe care cineva o scoate — iar
#: atunci nu mai prinde nici cazul adevărat.
def _is_pinned(statement: str, param: str) -> bool:
    pin = re.compile(
        rf"(?:{re.escape(param)}::\w+"          # cast explicit
        rf"|[\w.]+\s*(?:=|>=|<=|>|<)\s*{re.escape(param)}\b(?!\s*[-+]\s*(?:make_)?interval)"
        rf")", re.IGNORECASE)
    return bool(pin.search(statement))


#: Câte linii în jur se citesc ca fiind „aceeași instrucțiune".
#:
#: SQL-ul din modulele astea e scris ca literal multi-linie; douăzeci de linii
#: acoperă orice interogare din arbore fără să atingă pe următoarea.
STATEMENT_LINES = 20


def test_no_bound_parameter_enters_time_arithmetic_without_a_cast() -> None:
    """Forma care a doborât ingestia pe 24 august 2026.

    `closed_at >= $2 - interval '1 day'`, cu `$2` nefolosit nicăieri altundeva:
    Postgres deduce `interval` pentru el, iar comparația devine
    `timestamptz >= interval`. Instrucțiunea nu se compilează, runda eșuează, iar
    colectorul se oprește pentru TOATE sursele — nu doar pentru cea care a adus
    interogarea nouă. Măsurat: ingestia a fost picată douăzeci de minute.
    """
    gasite: list[str] = []
    for path in _sources():
        linii = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(linii, start=1):
            for m in UNTYPED.finditer(line):
                if TYPED.search(m.group(0)):
                    continue
                param = re.match(r"\$\d+", m.group(0)).group(0)
                jur = "\n".join(linii[max(0, i - 1 - STATEMENT_LINES):i + STATEMENT_LINES])
                if _is_pinned(jur, param):
                    continue
                rel = path.relative_to(ROOT).as_posix()
                gasite.append(f"{rel}:{i} — {line.strip()[:110]}")

    assert not gasite, (
        "parametru fără cast într-o aritmetică de timp, și nefixat altundeva:\n    "
        + "\n    ".join(gasite)
        + "\n\nScrie `$N::timestamptz - interval '…'`. Fără cast, Postgres "
          "deduce `interval` pentru parametru și instrucțiunea nu se compilează "
          "— iar runda întreagă a colectorului eșuează, nu doar interogarea asta.")


def test_the_guard_accepts_a_parameter_pinned_elsewhere() -> None:
    """`WHERE ts >= $3 AND ts < $3 + interval '1 minute'` funcționează.

    Prima comparație îi dă lui `$3` tipul lui `ts`, deci a doua e neambiguă.
    Forma asta există în `detect/rules.py` de luni de zile. O gardă care ar
    respinge-o ar cere o rescriere fără niciun câștig — și ar învăța pe cineva că
    garda greșește, ceea ce e cel mai scurt drum către ștergerea ei.
    """
    fixat = "WHERE ts >= $3 AND ts < $3 + interval '1 minute'"
    nefixat = "WHERE session_key = $1 AND closed_at >= $2 - interval '1 day'"

    assert _is_pinned(fixat, "$3")
    assert not _is_pinned(nefixat, "$2"), (
        "garda crede că `$2` e fixat, deși singura lui folosire e chiar "
        "aritmetica de timp — adică n-ar fi prins defectul din 24 august")
    assert _is_pinned(nefixat, "$1")


def test_the_guard_can_actually_tell_the_two_forms_apart() -> None:
    """Garda gărzii.

    Un tipar care potrivește și forma corectă ar fi la fel de inutil ca unul care
    nu potrivește nimic: în primul caz ar țipa la cod bun până îl comentează
    cineva, în al doilea ar tăcea pentru totdeauna. Aici se cere amândouă.
    """
    rau = "WHERE closed_at >= $2 - interval '1 day'"
    bun = "WHERE closed_at >= $2::timestamptz - interval '1 day'"

    assert UNTYPED.search(rau), "garda nu vede forma care a picat în producție"
    m = UNTYPED.search(bun)
    assert m is None or TYPED.search(m.group(0)), (
        "garda țipă și la forma corectă, deci e o gardă pe care cineva o va scoate")

    assert TYPED.search(bun)
    assert not TYPED.search(rau)


def test_the_search_actually_walks_the_shipped_code() -> None:
    """O căutare pe zero fișiere trece verde și nu vede nimic.

    Aceeași scăpare pe care o păzește `test_repo_is_sanitised` pentru scanarea
    lui: un tipar care nu întâlnește niciodată nicio linie arată identic cu un
    depozit curat.
    """
    fisiere = _sources()
    assert len(fisiere) > 50, f"doar {len(fisiere)} fișiere căutate"
    nume = {p.name for p in fisiere}
    assert "logins.py" in nume
    assert "shipper.py" in nume
