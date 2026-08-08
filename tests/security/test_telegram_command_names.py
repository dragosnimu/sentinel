"""Numele comenzilor Telegram, validate înainte să ajungă pe server.

Un alias cu diacritic — `știu` — a oprit tot canalul de alertare. Telegram
acceptă doar `[a-z0-9_]` într-un nume de comandă, iar `python-telegram-bot`
ridică `ValueError` la ÎNREGISTRARE, nu la folosire. Botul murea în
`build_application`, înainte de a porni, și systemd îl repornea la nesfârșit:
contorul ajunsese la 1113 când a fost observat.

Costul nu e proporțional cu greșeala. Comanda nouă n-ar fi mers — asta ar fi
fost în regulă. În schimb a murit canalul prin care un agent de securitate îți
spune orice, timp de aproape o zi, în tăcere.

Verificarea e statică: numele sunt literale în tabelele de înregistrare, deci se
pot citi fără să pornim nimic și fără biblioteca de Telegram instalată.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

# Poarta documentată în docs/TESTARE.md e `pytest -m security`. Fără marcaj,
# verificarea care apără canalul de alertare ar fi deselectată exact de comanda
# scrisă ca să o ruleze.
pytestmark = pytest.mark.security

BOT = Path(__file__).resolve().parents[2] / "sentinel" / "telegram" / "bot.py"

# Regula lui Telegram, nu a noastră: litere mici ASCII, cifre, underscore, 1-32.
VALID = re.compile(r"^[a-z0-9_]{1,32}$")

# Marcaj pentru un nume care nu e literal în sursă. Nu trece validarea,
# dinadins: un nume care nu poate fi citit static nu poate fi declarat corect,
# iar aici greşeala costă tot canalul de alertare.
_UNVERIFIABLE = "<construit dinamic>"


def _command_names() -> list[tuple[str, int]]:
    """Fiecare nume care ajunge la `CommandHandler`, cu linia lui.

    Două surse, fiindcă una singură se poate ocoli:

    * tabelele `(("nume", "alias"), handler)` — forma obişnuită;
    * orice `CommandHandler("nume", ...)` scris direct, oriunde în fişier.

    A doua a fost adăugată după ce un verificator a demonstrat că o comandă
    înregistrată direct, în afara ambelor tabele, trece prin toată suita cu un
    diacritic în nume — adică exact avaria pe care testul există s-o prevină.

    Citite din AST, nu cu o expresie regulată peste text: un nume construit
    dintr-o variabilă ar scăpa unei potriviri textuale, iar testul ar trece fix
    pentru cazul pe care nu-l poate vedea.
    """
    tree = ast.parse(BOT.read_text(encoding="utf-8"), filename=str(BOT))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        # Tabelele: o listă de tupluri (tuplu_de_nume, handler).
        if isinstance(node, ast.Tuple) and len(node.elts) == 2:
            names, _handler = node.elts
            if isinstance(names, ast.Tuple):
                for elt in names.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        found.append((elt.value, elt.lineno))
        # Înregistrarea directă, oriunde, sub oricare dintre formele acceptate.
        #
        # `CommandHandler` primeşte `Union[str, Collection[str]]`, deci
        # `CommandHandler(["ping", "vulnerabilități"], ...)` e legal şi omoară
        # botul la fel de sigur. O primă versiune verifica doar `ast.Constant` şi
        # trecea peste forma-listă — suita rămânea verde în timp ce biblioteca
        # ridica ValueError la construire.
        #
        # `ast.Attribute` acoperă `ext.CommandHandler(...)`, scris cu numele
        # modulului în faţă.
        if isinstance(node, ast.Call):
            func = node.func
            name = (func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute) else None)
            if name == "CommandHandler":
                # `command=` scris pe nume lasa `node.args` gol. O versiune
                # anterioara cerea `node.args`, deci forma asta sarea peste tot
                # blocul.
                first = next((k.value for k in node.keywords if k.arg == "command"),
                             node.args[0] if node.args else None)
                if first is None:
                    continue
                items = (first.elts if isinstance(first, (ast.List, ast.Tuple, ast.Set))
                         else [first])
                for item in items:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str):
                        found.append((item.value, node.lineno))
                    elif isinstance(item, ast.Name) or (
                            isinstance(item, ast.Call)
                            and isinstance(item.func, ast.Name)
                            and item.func.id in ("list", "tuple", "set", "sorted")
                            and len(item.args) == 1
                            and isinstance(item.args[0], ast.Name)):
                        # Variabilă simplă, sau o conversie peste ea: forma
                        # `for names, handler in tabel`, iar numele din tabel
                        # sunt deja citite mai sus. A le semnala aici ar face
                        # testul să pice pe cod corect — iar un test care pică pe
                        # cod bun e următorul pe care cineva îl slăbeşte.
                        pass
                    else:
                        # f-string, concatenare, apel de funcţie. Nu poate fi
                        # citit static, deci nu poate fi declarat corect —
                        # iar tăcerea ar fi cea mai proastă ieşire: numele ar
                        # arăta verificat fără să fie.
                        found.append((_UNVERIFIABLE, node.lineno))
    return found



def test_the_registration_tables_are_actually_found() -> None:
    """Fără asta, o schimbare de formă ar face testul să nu vadă nimic și să
    treacă — verde, gol, inutil."""
    names = _command_names()
    assert len(names) >= 20, f"am găsit doar {len(names)} nume; formatul s-a schimbat?"
    assert any(n == "status" for n, _ in names)


def test_every_command_name_is_valid_for_telegram() -> None:
    offenders = [f"{name!r} (linia {line})"
                 for name, line in _command_names() if not VALID.match(name)]
    assert not offenders, (
        "nume de comandă respinse de Telegram: " + ", ".join(offenders)
        + "\n  Doar [a-z0-9_], maxim 32. python-telegram-bot ridică ValueError la "
          "înregistrare, deci botul nu pornește deloc — nu doar comanda aceea."
    )


def test_no_command_name_is_registered_twice() -> None:
    """Al doilea `add_handler` pentru același nume nu crapă; pur și simplu nu se
    execută niciodată. O comandă care tace e mai greu de observat decât una care
    dă eroare."""
    from collections import Counter

    dupes = [n for n, c in Counter(n for n, _ in _command_names()).items() if c > 1]
    assert not dupes, f"nume înregistrate de mai multe ori: {dupes}"


# ---------------------------------------------------------------------------
# Verificarea autoritara: construieste aplicatia REALA
# ---------------------------------------------------------------------------
# Testul de mai sus a fost reparat de trei ori, si de fiecare data un verificator
# a gasit o alta forma sintactica prin care un nume invalid trece: forma-lista,
# `ext.CommandHandler`, un rand de tabel scris cu paranteze drepte, o bucla peste
# un tuplu de nume, argumente pe nume. Peticirea urmatoarei forme e o cursa
# pierduta — mereu exista una la care nu m-am gandit.
#
# `python-telegram-bot` valideaza fiecare nume la inregistrare. Construind
# aplicatia reala, verificam EFECTUL, nu modelul nostru despre efect — pentru
# orice forma scrisa in corpul SINCRON al lui `build_application`.
#
# NU acopera `post_init`: acela e doar atribuit la construire si ruleaza abia la
# `Application.initialize()`. Un handler inregistrat acolo ar scapa de tot, iar
# un verificator a demonstrat-o. De aceea santinela AST interzice separat
# `add_handler` in `post_init` — vezi testul de mai jos.
#
# Verificarea prin AST ramane: e rapida, nu are nevoie de biblioteca, si da un
# mesaj care numeste linia. E o santinela, nu autoritatea.

def _fake_secrets():
    """Nu se conecteaza nimic: `build_application` doar inregistreaza handlere,
    iar `post_init` ruleaza abia la pornire.

    Tokenul e deliberat scurt si fara forma de token. O prima versiune folosea
    `NNNNNNNNN:AAH...`, forma reala — si garda de sanitizare a depozitului a
    picat testul, corect: un sir cu forma unui token intr-un depozit public nu
    poate fi deosebit de unul adevarat, iar o garda care incearca sa ghiceasca
    nu mai e o garda.
    """
    from types import SimpleNamespace
    return SimpleNamespace(require=lambda k: "0:test",
                           has=lambda k: True, get=lambda k, d=None: None)


def test_the_real_application_can_be_built():
    """Singurul test care ar fi prins avaria de la 8 august, oricum ar fi fost
    scrisa comanda.

    `build_application` nu era apelat de niciun test. Biblioteca nu valida nimic
    in suita, deci un diacritic ajungea pe server si oprea canalul de alertare
    pana observa cineva ca nu mai vin alerte.
    """
    from sentinel.config import Config
    from sentinel.telegram import bot

    # Doar constructia. Comparatia dintre ce scrie in sursa si ce s-a inregistrat
    # sta in testul ei, pe multimi — o versiune anterioara o facea aici, pe
    # numere, si pica pe refactorul legitim `CommandHandler(list(names), ...)`,
    # unde un handler acopera mai multe nume.
    bot.build_application(Config(), _fake_secrets())


def test_the_library_really_rejects_a_bad_name():
    """Fara asta, testul de mai sus e gol.

    Daca `python-telegram-bot` ar inceta sa valideze numele, constructia ar
    reusi si testul precedent ar ramane verde fara sa mai verifice nimic — exact
    forma de bifa falsa pe care fisierul asta o pazeste.
    """
    import pytest as _pytest
    from telegram.ext import CommandHandler

    with _pytest.raises(ValueError):
        CommandHandler("știu", lambda *_: None)


def test_no_handler_is_registered_outside_the_synchronous_body():
    """Verificarea autoritara construieste aplicatia; hook-urile ruleaza mai tarziu.

    `post_init` si `post_shutdown` sunt doar ATRIBUITE la construire si ruleaza
    abia la `Application.initialize()`. Un handler inregistrat acolo trece prin
    tot: aplicatia se construieste curat local, iar `ValueError` apare la
    pornirea pe server, cand systemd intra in bucla si canalul de alertare tace.

    O prima versiune cauta functia dupa NUME (`post_init`). O redenumire o
    dezactiva complet, si un verificator a demonstrat-o cu `_bootstrap`. Acum
    interdictia se aplica oricarei functii imbricate in `build_application` —
    numele ei nu conteaza, pozitia da.
    """
    tree = ast.parse(BOT.read_text(encoding="utf-8"), filename=str(BOT))
    offenders: list[str] = []

    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == "build_application"):
            continue
        for inner in ast.walk(node):
            if inner is node or not isinstance(
                    inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in ast.walk(inner):
                if (isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr in ("add_handler", "add_handlers")):
                    offenders.append(f"{inner.name}() linia {call.lineno}")

    assert not offenders, (
        "handler inregistrat intr-o functie imbricata: " + ", ".join(offenders)
        + ".\n  Nu e verificat de nimic — aplicatia se construieste curat, iar "
          "eroarea apare abia la initialize(), pe server.")


def test_the_registered_names_match_what_the_source_says():
    """Verificare incrucisata pe MULTIMI, nu pe numere.

    Doua versiuni anterioare au esuat aici. `>= 40` lasa opt handlere de joc.
    `total >= len(nume_din_AST)` nu putea observa stergeri — ambele scad
    impreuna — si pica pe un refactor legitim: `CommandHandler(names, ...)`
    inregistreaza un handler pentru mai multe nume, deci numerele diverg fara ca
    nimic sa fie gresit.

    Multimile nu au niciuna dintre problemele astea. PTB expune `commands` pe
    fiecare handler, deja in litere mici — exact ce va accepta Telegram.
    """
    from sentinel.config import Config
    from sentinel.telegram import bot

    app = bot.build_application(Config(), _fake_secrets())
    registered = {c for hs in app.handlers.values() for h in hs
                  for c in getattr(h, "commands", ())}
    from_source = {n.lower() for n, _ in _command_names() if VALID.match(n)}

    assert from_source, "santinela AST nu mai gaseste niciun nume"
    missing = from_source - registered
    assert not missing, (
        f"nume scrise in sursa dar neinregistrate: {sorted(missing)} — "
        "comanda exista in cod si nu raspunde niciodata")
