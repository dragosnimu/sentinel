"""Nicio cale de ieșire spre Telegram nu rămâne nenumită.

Eșecul prevenit: **27 august 2026, două instanțe, opt ore de alerte despre
mașina greșită.** Un Sentinel de test a primit tokenul producției; din 13:10
până a doua zi la 08:32 două instanțe au alertat în același chat, și niciun
mesaj nu spunea de pe care mașină venea.

Reparația marchează mesajele în două locuri, fiindcă există exact două
transporturi: `StampingBot` din `sentinel/telegram/bot.py`, prin care trece tot
ce pleacă din procesul botului, și `sentinel/telegram/direct.py`, care nu trece
prin bot deloc — folosit de autoverificare atunci când botul e chiar lucrul
căzut, de anunțul de vulnerabilități și de `sentinel telegram --send-test`.

Testele de comportament stau în `tests/unit/test_telegram_instance_tag.py`.
Fișierul ăsta păzește altceva: **că nu apare un al patrulea drum**. O cale
ratată nu se vede niciodată la scriere; se vede peste o lună, în mesajul care
confuză din nou.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PACHET = REPO / "sentinel"

#: Cine are voie să cheme transportul direct, și în ce funcție. Fiecare
#: intrare de aici a fost citită și marchează textul înainte de a-l trimite.
APELANTI_CUNOSCUTI = {
    ("scan/announce.py", "announce"),
    ("selfcheck/runner.py", "_send_direct"),
    ("services/telegram_service.py", "_send_test"),
}

#: Unde are voie să apară gazda API-ului. Orice alt fișier care o scrie
#: construiește un al treilea transport, care n-ar trece prin niciunul dintre
#: cele două locuri unde se pune numele instanței.
FISIERE_CU_GAZDA_API = {"telegram/direct.py", "constants.py"}


def _fisiere() -> list[Path]:
    return sorted(p for p in PACHET.rglob("*.py")
                  if "__pycache__" not in p.parts)


def _relativ(path: Path) -> str:
    return path.relative_to(PACHET).as_posix()


def _apeluri_catre(nume: str) -> set[tuple[str, str]]:
    """Perechile (fișier, funcție care conține apelul), pentru un nume de apel.

    Se caută prin AST, nu prin text: un `send_to_chats` scris într-un comentariu
    sau într-un docstring nu e un apel, iar unul scris pe două rânduri e.
    """
    gasite: set[tuple[str, str]] = set()
    for path in _fisiere():
        arbore = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for nod in ast.walk(arbore):
            if not isinstance(nod, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for apel in ast.walk(nod):
                if not isinstance(apel, ast.Call):
                    continue
                tinta = apel.func
                ok = (isinstance(tinta, ast.Name) and tinta.id == nume) or \
                     (isinstance(tinta, ast.Attribute) and tinta.attr == nume)
                if ok:
                    gasite.add((_relativ(path), nod.name))
    return gasite


def test_the_ast_sentinel_actually_finds_something():
    """Fără asta, tot ce urmează poate trece pe o mulțime goală.

    În depozitul ăsta au trecut deja teste care nu verificau nimic: un grep
    după un tipar inexistent, o listă parametrizată ieșită goală și sărită
    tăcut. Fiecare a costat o pană ca să fie descoperit.
    """
    assert _apeluri_catre("send_to_chats"), (
        "santinela AST nu mai găsește niciun apel către `send_to_chats` — "
        "s-a redenumit transportul direct, iar verificările de mai jos au "
        "devenit goale.")


def test_no_unreviewed_path_sends_to_telegram_without_the_bot():
    """Un al patrulea apelant al transportului direct ar fi nenumit.

    `StampingBot` acoperă tot ce pleacă prin procesul botului. Ce cheamă
    `telegram/direct.py` îl ocolește prin construcție, deci trebuie să-și pună
    singur numele instanței — și cine adaugă un asemenea apel trebuie să afle
    asta atunci, nu din următorul incident.
    """
    gasite = _apeluri_catre("send_to_chats")
    # Definiția însăși nu e un apel; funcția din `direct.py` nu se autoapelează.
    noi = gasite - APELANTI_CUNOSCUTI
    assert not noi, (
        f"apel nou către `send_to_chats`: {sorted(noi)}.\n"
        "  Calea asta nu trece prin `StampingBot`, deci mesajul ei nu spune de "
        "pe ce mașină vine. Marchează textul cu "
        "`sentinel.telegram.identity.stamp(text, tag_for(cfg))` și adaugă "
        "apelantul în `APELANTI_CUNOSCUTI`.")

    lipsa = APELANTI_CUNOSCUTI - gasite
    assert not lipsa, (
        f"apelant declarat dar negăsit: {sorted(lipsa)}. Lista de mai sus e "
        "acum mai largă decât realitatea, deci nu mai păzește nimic.")


def test_each_direct_caller_stamps_before_it_sends():
    """Nu e destul să fie pe listă: fiecare trebuie să CHEME marcarea.

    Aserțiunea e pe apelul lui `stamp` în aceeași funcție, nu pe prezența
    numelui undeva în fișier — o aserțiune pe prezența unui nume în loc de pe
    decizia luată din el a trecut deja verde în depozitul ăsta.
    """
    marcheaza = _apeluri_catre("stamp")
    nemarcati = APELANTI_CUNOSCUTI - marcheaza
    assert not nemarcati, (
        f"trimit fără să marcheze: {sorted(nemarcati)} — mesajele lor nu spun "
        "de pe ce instanță vin.")


@pytest.mark.parametrize("path", _fisiere(), ids=_relativ)
def test_only_the_shared_transport_talks_to_the_telegram_api(path: Path):
    """Un al treilea transport, scris cu httpx de mână, ar ocoli ambele locuri
    în care se pune numele — și, la fel de rău, ambele locuri în care se
    verifică dacă mesajul chiar a ajuns (vezi `telegram/direct.py`)."""
    text = path.read_text(encoding="utf-8")
    if "api.telegram.org" not in text:
        return
    assert _relativ(path) in FISIERE_CU_GAZDA_API, (
        f"{_relativ(path)} scrie gazda API-ului Telegram. Dacă e un transport "
        "nou, el nu marchează instanța și nu verifică livrarea; folosește "
        "`sentinel/telegram/direct.py`.")
