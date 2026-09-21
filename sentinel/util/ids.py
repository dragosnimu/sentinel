"""Un id tastat de om, transformat în ceva ce se poate da bazei de date.

Un loc, fiindcă răspunsul fusese deja scris de trei ori, diferit, în trei zile:

  * `web/routers/findings.py` — `isascii() and isdigit()`, plafon de cifre,
    `>= 1`. Cea mai completă dintre cele trei: plafonul de nouă cifre e și o
    margine de sus, doar că una de LUNGIME, potrivită pentru un număr de
    pagină — care nu ajunge în nicio coloană — nu pentru un id de rând;
  * `telegram/bot.py` — `.isdecimal()`, cu un comentariu de nouă rânduri despre
    `'²'`. Acceptă cifrele zecimale non-ASCII (arabo-indice), pe care `int()`
    chiar le parsează;
  * `telegram/views.py` — `.isdigit()` simplu, care lasă `'²'` să treacă până la
    `int()` și ridică `ValueError` în handler.

Trei variante înseamnă că a patra e o chestiune de timp, iar fiecare a fost
scrisă pentru cazul care o omorâse pe cea dinainte.

## Ce refuză, și de ce fiecare refuz e măsurat

`isascii() and isdigit()` — adică exact `0`-`9`. `'²'.isdigit()` e `True` iar
`int('²')` ridică `ValueError`; `'٢'` (arabo-indic) trece prin `int()` și
înseamnă 2, dar un „٢" într-o comandă nu e ce a vrut cineva să scrie — e mai
cinstit să spunem că nu l-am înțeles decât să ghicim.

**Lungimea se verifică ÎNAINTE de conversie.** CPython refuză `int()` peste
4300 de cifre (`sys.set_int_max_str_digits`), deci verificarea care curăță
argumentul l-ar transforma ea însăși într-o excepție.

**Marginea de sus vine din tipul coloanei.** Toate id-urile pe care le caută
comenzile astea stau în coloane `bigserial` (`findings`, `incidents`,
`patch_plans` — migrațiile 0003, 0001, 0004), deci în `bigint`. Cheia aici e
că `9223372036854775808` are 19 cifre ASCII, trece de `isdigit()`, trece de
`int()` — și e refuzat abia pe fir, de asyncpg, cu `DataError: value out of
int64 range`. Adică o excepție în handler, adică „A apărut o eroare la
procesarea comenzii" pentru operator și un traceback în journal, dintr-un
argument de 19 caractere.

Nimic de aici nu face o interogare și nimic nu escapează text: întoarce un
`int` pe care apelantul îl poate trimite mai departe, sau `None` când argumentul
nu e un id, și apelantul decide ce spune despre asta.
"""

from __future__ import annotations

#: Cea mai mare valoare pe care o duce o coloană `bigint` din Postgres.
#: Peste ea, asyncpg refuză parametrul înainte ca interogarea să plece.
BIGINT_MAX = 2**63 - 1


def parse_id(raw: str | None, *, maximum: int = BIGINT_MAX) -> int | None:
    """Valoarea, sau `None` când argumentul nu e un id utilizabil.

    `None` acoperă toate felurile de „nu e un id": lipsă, cu alte caractere
    decât cifre ASCII, zero sau negativ, prea lung, sau peste `maximum`.
    Apelantul are un singur lucru de spus operatorului — „nu e un id" — și nu
    trebuie să aleagă între cinci mesaje pentru cinci feluri de a greși.

    `maximum` e marginea lumii în care se caută: implicit `bigint`, fiindcă
    acolo stau id-urile; pagina îi dă propria margine, care n-are nicio
    legătură cu o coloană.
    """
    if raw is None:
        return None
    text = raw.strip()
    # Ordinea contează: mulțimea de caractere, apoi lungimea, abia apoi `int()`.
    # Inversate, un șir de 4301 de cifre ar ajunge la conversie și ar ridica
    # ValueError chiar în verificarea pusă să-l oprească.
    if not text.isascii() or not text.isdigit():
        return None
    if len(text) > len(str(maximum)):
        return None
    value = int(text)
    if value < 1 or value > maximum:
        return None
    return value
