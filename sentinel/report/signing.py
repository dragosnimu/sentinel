"""Forma canonică peste care se semnează, și semnătura însăși.

Contractul modulului ăstuia nu e „produce un JSON", e **identitatea de octeți cu
`canonical()` din `aggregator/lib/verify.ts`**. Cele două capete calculează HMAC
peste octeții pe care fiecare îi produce din același obiect; dacă diferă un
singur octet, semnătura nu se verifică NICIODATĂ, iar simptomul e un 401 — adică
exact ce s-ar vedea la o cheie greșită. Se pierde o zi căutând în locul
nepotrivit, timp în care martorul nu primește nimic.

## De ce nu `json.dumps` / `JSON.stringify`

Fiindcă s-a încercat, și nu ține. Măsurate pe 12 payload-uri trecute prin ambele
implementări în timpul lui E1, cele două serializatoare de uz general nu erau de
acord pe patru intrări, plus una atinsă din configurație:

| intrare | Python | JavaScript |
|---|---|---|
| chei care arată ca întregi | `{"1":…,"10":…,"2":…}` | `{"1":…,"2":…,"10":…}` |
| aceleași, imbricate | `{"10":1,"2":2}` | `{"2":2,"10":1}` |
| exponent | `1e-07` | `1e-7` |
| float întreg (`interval_s: 60.0`) | `60.0` | `60` |
| sortare peste BMP | `…"\\uE000","\\uFFFD","\\U0001F600"` | `…"\\U0001F600","\\uE000","\\uFFFD"` |

Cauzele sunt trei, și niciuna nu se repară din partea noastră: obiectele
JavaScript reașază cheile de tip index în ordine numerică, deci o sortare urmată
de reconstrucție se anulează singură; `Array.sort()` compară unități UTF-16, nu
puncte de cod; iar cele două limbaje au algoritmi diferiți de număr-către-șir.

**A încerca să faci două serializatoare de uz general să fie de acord e un
contract care ține până când adaugă cineva un câmp.** Ține azi fiindcă payload-ul
de azi e sărac, iar sărăcia aia nu e o proprietate pe care s-o apere ceva.

Deci: **emitem octeții explicit, la ambele capete**, după regulile scrise mai
jos. Niciun apel la `json.dumps`. Ce nu e scris aici nu se serializează.

## Contractul: ce se acceptă

Un payload valid e un **dicționar** în care:

* **cheile** sunt `str`, cu toate caracterele în ASCII tipăribil (U+0020-U+007E).
  Nu fiindcă n-am putea sorta altceva — comparatorul de la celălalt capăt e
  explicit pe puncte de cod — ci fiindcă o cheie e un nume de câmp dintr-un
  protocol pe care îl scriem noi, iar un nume de câmp în afara ASCII e o greșeală,
  nu o cerință. Restricția șterge o clasă întreagă de divergență cu preț zero.
  Cheile care arată ca întregi (`"1"`, `"10"`) sunt PERMISE și ies în ordinea
  punctelor de cod la ambele capete, fiindcă nu reconstruim niciun obiect.
* **valorile** sunt: `None`, `bool`, `int`, `str`, listă sau dicționar.
  * `int` doar în intervalul întregilor exacți din IEEE-754 (±2^53-1). Peste el,
    JavaScript nu mai poate reprezenta valoarea exact, deci un receptor care
    recalculează forma canonică ar obține alți octeți — și ar refuza un semnal
    corect.
  * **`float` e refuzat, fără excepție.** Nu se convertește tăcut la `int` nici
    când e întreg: `60.0` și `60` sunt aceeași valoare pentru un om și două
    șiruri diferite pentru un serializator, iar conversia tăcută ar muta decizia
    din locul unde se poate observa în locul unde nu se poate. `NaN` și
    `Infinity` nu sunt nici măcar JSON valid.
  * șirurile pot conține orice punct de cod Unicode ATRIBUIBIL — diacriticele
    românești și emoji-urile trec neatinse, fiindcă valorile nu se sortează, deci
    ordinea peste BMP nu contează. Surogații neîmperecheați se refuză: Python nu
    îi poate codifica în UTF-8, JavaScript îi scrie ca `\\udXXX`, deci sunt
    singura formă de șir pe care cele două capete NU o pot scrie la fel.
* adâncimea de imbricare e cel mult 32. Fluxurile din E2 duc rânduri cu blob-uri
  JSON influențate de atacator; o recursie nemărginită într-o primitivă de
  semnare e o cădere de proces, nu o eroare de validare.

Tuplele, `Decimal`, `datetime`, `bytes`, `set` — refuzate. Fiecare ar avea o
serializare „evidentă" pe care celălalt capăt n-o cunoaște.

## De ce validatorul refuză în loc să repare

Un validator care repară nu e un validator, e un al doilea serializator — și
atunci ai iar două implementări care pot să nu fie de acord. Refuzul are singura
proprietate care contează aici: **pentru orice payload pe care validatorul îl
acceptă, cele două capete produc aceiași octeți**, iar asta se demonstrează
rulându-le pe amândouă (`tests/unit/test_signing.py` și
`aggregator/tests/canonical.test.ts`, pe corpusul comun din
`tests/fixtures/canonical-corpus.json`), nu raționând despre ele.

## Ce se întâmplă când refuză

`CanonicalError` **la expeditor**, nu octeți pe care receptorul îi va respinge.
Diferența contează: octeții respinși la celălalt capăt se văd ca un 401 fără
cauză, în timp ce excepția de aici numește câmpul.

`send_once` din `beacon.py` o prinde și ratează runda — bucla trăiește, ca la
lipsa de identitate. Trebuie spus limpede ce costă asta: o rundă ratată e tăcere
către martor, iar trei la rând înseamnă alarmă critică despre un server sănătos.
E prețul acceptat dinadins, cu două contragreutăți. Prima: singura cale prin care
un payload real putea ieși din contract era un `float` venit din `sentinel.yaml`,
iar aia e închisă acum la sursă în `_coerce` (`sentinel/config.py`). A doua:
alternativa — să semnăm orice și să lăsăm agregatorul să decidă — e chiar tiparul
din `CLAUDE.md`, confirmarea intenției în locul efectului, mutată cu un nivel mai
jos.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from sentinel.errors import SentinelError

__all__ = ["MAX_DEPTH", "MAX_SAFE_INT", "CanonicalError", "canonical", "sign"]

# Cel mai mare întreg pe care IEEE-754 pe 64 de biți îl reprezintă exact, adică
# limita lui `Number` din JavaScript. Peste el, `9007199254740993` devine
# `9007199254740992` la celălalt capăt și octeții nu mai coincid.
MAX_SAFE_INT = 2**53 - 1

MAX_DEPTH = 32

# Exact aceleași scurtături ca la celălalt capăt, scrise ca listă închisă în loc
# să fie moștenite de la un serializator: restul controlelor C0 ies `\u00xx` cu
# hexa MINUSCULĂ, iar DEL (0x7f) NU se escapează.
_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

_KEY_MIN = 0x20
_KEY_MAX = 0x7E


class CanonicalError(SentinelError):
    """Payload-ul iese din contractul de semnare.

    Nu e retryabilă: aceiași octeți vor eșua la fel data viitoare. Cine o prinde
    trebuie să rateze operația, nu s-o reia.
    """


def canonical(payload: Any) -> bytes:
    """Octeții exacți peste care se calculează semnătura.

    Ridică `CanonicalError` pentru orice payload în afara contractului din capul
    modulului.
    """
    if not isinstance(payload, dict):
        raise CanonicalError(
            f"$: payload-ul de semnat trebuie să fie un dicționar, "
            f"nu {type(payload).__name__}")
    out: list[str] = []
    _emit(payload, out, "$", 0)
    # `strict` e implicit și rămâne așa dinadins: dacă vreodată scapă un surogat
    # pe lângă verificarea de mai jos, vrem excepție, nu un `?` tăcut în octeții
    # peste care semnăm.
    return "".join(out).encode("utf-8")


def sign(payload: Any, secret: str) -> str:
    """HMAC-SHA256 hexa peste forma canonică. Ridică `CanonicalError` ca ea."""
    return hmac.new(secret.encode("utf-8"), canonical(payload),
                    hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Emitentul. O singură parcurgere: validează ȘI scrie.
#
# Nu două funcții, dinadins. Un validator separat de emitent e încă o pereche de
# implementări care pot să nu fie de acord — exact problema pe care modulul o
# rezolvă între limbaje, reintrodusă în interiorul unuia singur.
# ---------------------------------------------------------------------------
def _emit(value: Any, out: list[str], path: str, depth: int) -> None:
    if value is None:
        out.append("null")
        return
    # Înaintea lui `int`: în Python `bool` E `int`, iar `True` scris ca `1` ar
    # trece de validare și ar schimba semnalul fără să se plângă nimeni.
    if isinstance(value, bool):
        out.append("true" if value else "false")
        return
    if isinstance(value, int):
        if -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            out.append(str(value))
            return
        raise CanonicalError(
            f"{path}: întregul {value} depășește ±2^53-1, deci celălalt capăt "
            f"nu îl poate reprezenta exact")
    if isinstance(value, str):
        out.append(_emit_string(value, path))
        return
    if isinstance(value, float):
        raise CanonicalError(
            f"{path}: float ({value!r}) nu se poate semna — cele două capete îl "
            f"scriu diferit. Trimite un întreg, sau un șir dacă zecimalele contează")
    if isinstance(value, dict):
        _check_depth(path, depth)
        out.append("{")
        for i, key in enumerate(_sorted_keys(value, path)):
            if i:
                out.append(",")
            out.append(_emit_string(key, path))
            out.append(":")
            _emit(value[key], out, f"{path}.{key}", depth + 1)
        out.append("}")
        return
    if isinstance(value, list):
        _check_depth(path, depth)
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _emit(item, out, f"{path}[{i}]", depth + 1)
        out.append("]")
        return
    raise CanonicalError(
        f"{path}: tip neacceptat {type(value).__name__}. Contractul acceptă "
        f"None, bool, int, str, listă și dicționar")


def _check_depth(path: str, depth: int) -> None:
    if depth >= MAX_DEPTH:
        raise CanonicalError(
            f"{path}: imbricare peste {MAX_DEPTH} niveluri")


def _sorted_keys(value: dict[Any, Any], path: str) -> list[str]:
    """Cheile validate și puse în ordinea punctelor de cod.

    Ordinea e a lui `sorted()`, care pentru `str` compară puncte de cod. La
    celălalt capăt e un comparator explicit pe puncte de cod, nu `Array.sort()`.
    """
    for key in value:
        if not isinstance(key, str):
            raise CanonicalError(
                f"{path}: cheie {key!r} de tip {type(key).__name__}; cheile "
                f"trebuie să fie șiruri (json.dumps le-ar fi convertit tăcut)")
        for ch in key:
            if not _KEY_MIN <= ord(ch) <= _KEY_MAX:
                raise CanonicalError(
                    f"{path}: cheia {key!r} conține U+{ord(ch):04X}; cheile "
                    f"trebuie să fie ASCII tipăribil (U+0020-U+007E)")
    return sorted(value)


def _emit_string(text: str, path: str) -> str:
    out = ['"']
    for ch in text:
        escape = _ESCAPES.get(ch)
        if escape is not None:
            out.append(escape)
            continue
        cp = ord(ch)
        if cp < 0x20:
            out.append(f"\\u{cp:04x}")
        elif 0xD800 <= cp <= 0xDFFF:
            # Un surogat într-un `str` Python e mereu neîmperecheat: caracterele
            # din afara BMP sunt un singur punct de cod aici. `.encode("utf-8")`
            # ar ridica UnicodeEncodeError câteva rânduri mai jos; mesajul ăsta
            # spune care câmp, nu doar că a fost unul.
            raise CanonicalError(
                f"{path}: surogat neîmperecheat U+{cp:04X} într-un șir; cele "
                f"două capete nu îl pot scrie la fel")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)
