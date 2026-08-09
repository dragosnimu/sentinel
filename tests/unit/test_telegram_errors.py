"""O comanda care esueaza trebuie sa lase o urma din care se poate diagnostica.

Nu exista niciun test pe `_guard` inainte de fisierul asta, desi el e singurul
lucru care sta intre o comanda rupta si un bot mort — si singurul care decide ce
se afla despre esec.

Ce loga inainte: `extra={"detail": str(exc)}`. Pentru esecul de CHECK al lui
`/mute` a fost destul, fiindca asyncpg pune in mesaj si numele constrangerii, si
randul respins — deci acolo se vedeau si chat_id-ul, si valoarea. A tinut fiindca
exceptia venea din baza de date si purta randul cu ea, nu fiindca linia era
proiectata sa spuna asta.

Cazul in care nu tine e al doilea defect din acelasi fisier: `_fmt_local`,
apelat din trei locuri si nedefinit. Tot ce spunea linia veche era
`name '_fmt_local' is not defined` — fara chat, fara comanda, si fara sa
distinga intre `/mute 2h` si `/mute` cu o pauza activa. Testele de aici fixeaza
ce trebuie sa contina linia ca sa fie utila si in cazul asta.

Se verifica LINIA SCRISA, nu doar campurile de pe `LogRecord`: formatorul JSON e
cel care ajunge in journald, si un camp pus pe record dar necuprins in payload nu
ajuta pe nimeni la 3 dimineata.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.logging_setup import JSONFormatter, RedactingFilter  # noqa: E402
from sentinel.telegram import bot  # noqa: E402

# Id de fixtura, nu al operatorului. Depozitul e public, iar un chat id real
# leaga depozitul de contul lui de Telegram — pe lista de sanitizare scrie
# explicit „fara chat id".
#
# Telegram NU are un interval rezervat pentru exemple, cum are RFC 5737 pentru
# adrese: id-urile se aloca secvential, deci orice numar scris aici poate fi al
# cuiva. Sirul 1..0 e ales fiindca se citeste ca substituent din prima privire,
# iar codul nu trimite nimic catre el — valoarea intra in `allowed_chat_ids` si
# se compara doar cu ea insasi, prin jurnal. Nicio aserțiune nu depinde de ea.
FIXTURE_CHAT_ID = 1234567890
COMMAND = "/mute 22:00-06:00; vi,sa 22:00-09:00"


class Boom(Exception):
    """Sta pentru CheckViolationError: o exceptie ridicata adanc in scriere."""


def _run_guarded(exc: Exception, *, text: str = COMMAND,
                 chat_id: int = FIXTURE_CHAT_ID) -> list[str]:
    replies: list[str] = []

    async def reply_text(t, **_kw):
        replies.append(t)

    async def handler(update, context):
        raise exc

    handler.__name__ = "cmd_mute"

    message = SimpleNamespace(text=text, caption=None, reply_text=reply_text)
    update = SimpleNamespace(effective_chat=SimpleNamespace(id=chat_id),
                             effective_message=message, message=message)
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[chat_id]))
    context = SimpleNamespace(args=[], bot_data={"cfg": cfg})

    asyncio.run(bot._guard(handler)(update, context))
    return replies


def _failure_line(caplog) -> dict:
    records = [r for r in caplog.records if r.getMessage() == "telegram handler failed"]
    assert len(records) == 1, f"astept exact o linie de esec, am gasit {len(records)}"
    return json.loads(JSONFormatter("sentinel-telegram").format(records[0]))


@contextlib.contextmanager
def _journald_line():
    """Handlerul montat exact ca in `setup_logging`, si linia care ar pleca.

    Nu `caplog`: caplog nu are nici filtrul, nici formatorul, deci o aserțiune pe
    `record.<camp>` verifica o structura interna, nu octetii care ajung in
    journald. Aici se citeste ce s-ar scrie.
    """
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONFormatter("sentinel-telegram"))
    handler.addFilter(RedactingFilter())
    logger = logging.getLogger("sentinel.telegram.bot")
    logger.addHandler(handler)
    previous, logger.level = logger.level, logging.DEBUG
    try:
        yield stream
    finally:
        logger.removeHandler(handler)
        logger.level = previous


def test_a_failing_command_logs_the_exception_the_chat_and_the_command(caplog):
    """Cele patru lucruri fara de care linia depinde de norocul de a fi primit o
    exceptie vorbareata.

    Fara chat_id nu stii pe cine afecteaza. Fara textul comenzii nu stii ce sa
    reproduci — iar aici ARGUMENTUL declanseaza, nu numele comenzii. Fara
    traceback nu stii unde s-a rupt, si `/mute` atinge trei module. Fara tipul
    exceptiei, un mesaj gol nu spune nici macar ce fel de esec a fost.
    """
    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        replies = _run_guarded(Boom("new row violates check constraint "
                                    "\"telegram_chats_quiet_hours_shape\""))

    payload = _failure_line(caplog)
    assert payload["chat_id"] == FIXTURE_CHAT_ID
    assert "vi,sa 22:00-09:00" in payload["command"], \
        "argumentul lipseste din jurnal — exact el era defectul"
    assert "Boom" in payload["detail"]
    assert "telegram_chats_quiet_hours_shape" in payload["detail"]
    assert payload["handler"] == "cmd_mute"
    # Traceback-ul, nu doar numele exceptiei.
    assert "Traceback" in payload["exc"] and "raise exc" in payload["exc"]

    # Si operatorul primeste in continuare un raspuns: un bot mut e mai rau.
    assert replies == ["A apărut o eroare la procesarea comenzii."]


def test_a_nameerror_deep_in_a_command_is_still_locatable(caplog):
    """Cazul concret in care `str(exc)` singur nu ajunge.

    `_fmt_local` era apelat din trei locuri in `bot.py`. `str(NameError)` spune
    doar ce nume lipseste, nu si de pe care ramura s-a ajuns acolo — iar cele trei
    ramuri sunt comenzi diferite, cu reparatii diferite. Traceback-ul si textul
    comenzii sunt singurele care fac diferenta intre `/mute 2h` si `/mute`.
    """
    def raiser():
        return _fmt_local_care_nu_exista(1)      # noqa: F821 - exact tiparul reprodus

    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        try:
            raiser()
        except NameError as exc:
            _run_guarded(exc, text="/mute 2h")

    payload = _failure_line(caplog)
    assert payload["detail"].startswith("NameError")
    assert "_fmt_local_care_nu_exista" in payload["detail"]
    assert payload["command"] == "/mute 2h", \
        "fara textul comenzii nu se stie care dintre cele trei ramuri a picat"
    assert "in raiser" in payload["exc"], "traceback-ul nu numeste locul apelului"


def test_an_exception_with_no_message_still_names_its_type(caplog):
    """`str(Boom())` e sirul gol. O linie care loga doar atat nu ar contine
    nicio informatie despre ce s-a intamplat."""
    assert str(Boom()) == ""

    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        _run_guarded(Boom())

    payload = _failure_line(caplog)
    assert payload["detail"].startswith("Boom"), payload["detail"]
    assert "Boom" in payload["exc"]


def test_a_command_without_arguments_is_still_identified(caplog):
    """`/panic` nu are argumente. Linia trebuie sa spuna macar ce comanda a fost."""
    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        _run_guarded(Boom("nope"), text="/panic")

    assert _failure_line(caplog)["command"] == "/panic"


def test_the_logged_command_is_bounded(caplog):
    """Textul vine de la un client Telegram si lungimea lui nu e marginita de
    nimic din codul asta. O linie de jurnal de zeci de kiloocteti la fiecare
    eroare umple discul gazdei pe care Sentinel e musafir."""
    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        _run_guarded(Boom("nope"), text="/mute " + "x" * 5000)

    assert len(_failure_line(caplog)["command"]) <= 200


SECRET = "aBcDeF1234567890"


def test_no_field_of_the_failure_line_leaks_a_credential():
    """Aserțiune pe TOATA linia serializata, nu pe un camp ales.

    Prima varianta a testului asta numea riscul — „cineva lipeste un token intr-un
    chat" — si apoi asertea doar pe `command`, campul care era deja sigur. Trecea
    in timp ce `exc` scurgea secretul verbatim, fiindca `exc_info` si `exc_text`
    sunt in `_RESERVED` si `RedactingFilter` nu le atinge prin constructie. O
    garda care asertează pe altceva decat pe ce pazeste e mai rea decat lipsa ei:
    arata ca acoperire.

    Calea nu e ipotetica: mesajul unei violari de constrangere PostgreSQL citeaza
    randul respins, adica exact ce a tastat operatorul. Singura parte speculativa
    e ca textul acela contine o credentiala.
    """
    typed = f"/mute token={SECRET}"
    with _journald_line() as stream:
        _run_guarded(ValueError(f"bad value: token={SECRET}"), text=typed)

    line = stream.getvalue()
    assert line.strip(), "nu s-a scris nicio linie"
    payload = json.loads(line)          # redactarea nu are voie sa strice JSON-ul

    for field, value in payload.items():
        assert SECRET not in str(value), f"secretul a scapat in campul {field!r}: {value!r}"
    assert SECRET not in line, "secretul a scapat undeva in linie"

    # Si nu prin stergerea campurilor: informatia trebuie sa ramana utila.
    assert "REDACTED" in payload["command"] and "token" in payload["command"]
    assert "ValueError" in payload["exc"] and "Traceback" in payload["exc"]
    assert payload["chat_id"] == FIXTURE_CHAT_ID


def test_the_traceback_is_redacted_for_the_terminal_too(caplog):
    """`HumanFormatter` e folosit cand stderr e un tty. Aceeasi ocolire: baza
    `logging.Formatter` lipeste `exc_text`, pe care filtrul nu-l vede. Mai putin
    public decat journald, dar de acolo se copiaza in tichete si in chat."""
    from sentinel.logging_setup import HumanFormatter

    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        _run_guarded(ValueError(f"bad value: token={SECRET}"), text=f"/mute token={SECRET}")

    records = [r for r in caplog.records if r.getMessage() == "telegram handler failed"]
    rendered = HumanFormatter("sentinel-telegram").format(records[0])
    assert SECRET not in rendered, rendered
    assert "ValueError" in rendered


def test_an_unauthorized_chat_gets_silence_not_an_error_line(caplog):
    """Un chat neautorizat nu primeste niciun raspuns care sa confirme ca botul
    exista, si nu ajunge niciodata in handler."""
    async def handler(update, context):
        raise AssertionError("handlerul nu trebuia atins")

    replies: list[str] = []

    async def reply_text(t, **_kw):
        replies.append(t)

    message = SimpleNamespace(text="/mute off", caption=None, reply_text=reply_text)
    update = SimpleNamespace(effective_chat=SimpleNamespace(id=1),
                             effective_message=message, message=message)
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[FIXTURE_CHAT_ID]))
    context = SimpleNamespace(args=[], bot_data={"cfg": cfg})

    with caplog.at_level(logging.WARNING, logger="sentinel.telegram.bot"):
        asyncio.run(bot._guard(handler)(update, context))

    assert replies == []
    assert any(r.getMessage() == "unauthorized telegram command" for r in caplog.records)
