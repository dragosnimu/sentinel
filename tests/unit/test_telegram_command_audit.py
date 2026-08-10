"""Ce rămâne în urma unei comenzi reușite.

Al doilea defect din `telegram/bot.py`: `telegram_chats.commands_count` și
`last_command_at` există din migrația 0006 și nu erau scrise de nimic. Pe gazdă:
`0` și `NULL`, deși comenzile operatorului ajunseseră demonstrabil la handlere cu
o zi înainte — eroarea lor e în jurnal. Două coloane care arată exact ca un
istoric de comenzi, cu exact conținutul pe care l-ar avea un bot nefolosit, s-au
citit ca dovadă în timpul unui diagnostic și l-au trimis pe un drum greșit.

S-a ales scrierea, nu ștergerea: pentru un canal de control care poate bloca
adrese și goli firewall-ul, „a fost folosit, și ultima oară când" nu se putea
afla din nicio altă parte — botul nu loga deloc comenzile reușite. Coloanele
răspund la asta și supraviețuiesc rotației jurnalului; linia nouă de jurnal
spune CARE a fost comanda, lucru pe care două coloane nu-l pot ține.

Testele trec prin `_guard`, adică prin exact drumul pe care intră orice comandă.
"""
from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.db.repo import chats as chats_repo  # noqa: E402
from sentinel.telegram import bot  # noqa: E402

# Substituent, ca în celelalte teste de Telegram — depozitul e public.
CHAT_ID = 1234567890


class _DB:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self.error = error

    async def execute(self, sql, *args):
        if self.error is not None:
            raise self.error
        self.calls.append((sql, args))


def _run(handler, *, db=None, chat_id: int = CHAT_ID, allowed=(CHAT_ID,),
         text: str = "/status") -> list[str]:
    replies: list[str] = []

    async def reply_text(t, **_kw):
        replies.append(t)

    message = SimpleNamespace(text=text, caption=None, reply_text=reply_text)
    update = SimpleNamespace(effective_chat=SimpleNamespace(id=chat_id),
                             effective_message=message, message=message)
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=list(allowed)))
    bot_data = {"cfg": cfg}
    if db is not None:
        bot_data["db"] = db
    context = SimpleNamespace(args=[], bot_data=bot_data)

    asyncio.run(bot._guard(handler)(update, context))
    return replies


async def _ok(update, context):
    await update.message.reply_text("gata")


_ok.__name__ = "cmd_status"


# --- coloanele -------------------------------------------------------------
def test_o_comanda_acceptata_scrie_coloanele(caplog):
    """Fără asta, `commands_count` rămâne 0 pe o gazdă folosită zilnic — și
    cineva care se uită la ea în timpul unui incident concluzionează că botul nu
    primește nimic."""
    db = _DB()
    with caplog.at_level(logging.WARNING, logger="sentinel.telegram.bot"):
        assert _run(_ok, db=db) == ["gata"]

    assert len(db.calls) == 1, "comanda nu a fost înregistrată nicăieri"
    sql, args = db.calls[0]
    assert args == (CHAT_ID,)
    assert "telegram_chats" in sql
    assert "commands_count" in sql and "last_command_at" in sql


def test_contorul_se_incrementeaza_in_sql_nu_in_python():
    """Un `SELECT` urmat de un `UPDATE` pierde o comandă când două sosesc
    deodată — și exact atunci (o rafală de comenzi într-un incident) contorul e
    citit."""
    sql = _sql_of_record_command()
    assert re.search(r"commands_count\s*=\s*telegram_chats\.commands_count\s*\+\s*1", sql), sql
    assert "ON CONFLICT" in sql, "un chat fără rând de preferințe nu ar fi numărat deloc"


def test_coloanele_scrise_exista_in_schema():
    """Aserțiunea pe care nicio suită fără PostgreSQL nu o face altfel: un
    `INSERT` către o coloană inexistentă ar pica abia pe gazdă, la fiecare
    comandă, iar `_guard` l-ar înghiți într-un avertisment."""
    schema = (Path(__file__).resolve().parents[2] / "sentinel" / "db" / "migrations"
              / "0006_auth_audit.sql").read_text(encoding="utf-8")
    tabel = schema.split("CREATE TABLE telegram_chats", 1)[1].split(");", 1)[0]
    for column in _columns_written_by(_sql_of_record_command()):
        assert re.search(rf"^\s*{column}\b", tabel, re.M), \
            f"`{column}` nu există în telegram_chats"


def _sql_of_record_command() -> str:
    import inspect

    return inspect.getsource(chats_repo.record_command)


def _columns_written_by(sql: str) -> set[str]:
    """Coloanele din lista de INSERT, citite din SQL-ul real, nu enumerate aici:
    o listă scrisă de mână în test ar rămâne în urmă exact ca lista pe care
    testul o verifică."""
    inserted = re.search(r"INSERT INTO telegram_chats \(([^)]*)\)", sql, re.S)
    assert inserted, sql
    columns = {c.strip() for c in inserted.group(1).split(",")}
    assert {"commands_count", "last_command_at"} <= columns, columns
    return columns


def test_esecul_scrierii_nu_pierde_comanda(caplog):
    """Baza poate fi picată exact când operatorul dă `/panic`. Un contor nu are
    voie să mănânce comanda — dar nici să eșueze în tăcere, fiindcă atunci
    coloanele îngheață și se citesc mai târziu ca și cum ar fi la zi."""
    db = _DB(error=RuntimeError("connection is closed"))

    with caplog.at_level(logging.WARNING, logger="sentinel.telegram.bot"):
        assert _run(_ok, db=db) == ["gata"], "comanda nu s-a mai executat"

    warnings = [r for r in caplog.records
                if r.getMessage() == "command not recorded"]
    assert len(warnings) == 1
    assert warnings[0].chat_id == CHAT_ID
    assert "RuntimeError" in warnings[0].detail


def test_un_chat_neautorizat_nu_e_numarat(caplog):
    """Contorul e per chat permis. Dacă ar număra și ce vine de la străini, ar
    deveni un canal prin care oricine care știe numele botului scrie în baza de
    date."""
    db = _DB()
    with caplog.at_level(logging.WARNING, logger="sentinel.telegram.bot"):
        assert _run(_ok, db=db, chat_id=999) == []

    assert db.calls == []


def test_o_comanda_care_pica_e_totusi_numarata(caplog):
    """Scris ÎNAINTE de handler, dinadins: comenzile de ieri au ajuns la
    handlere și au crăpat acolo. Dacă s-ar număra doar succesele, coloanele ar
    arăta iar zero fix în ziua în care sunt consultate."""
    db = _DB()

    async def crapa(update, context):
        raise RuntimeError("boom")

    crapa.__name__ = "cmd_mute"

    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        _run(crapa, db=db)

    assert len(db.calls) == 1


# --- linia de jurnal -------------------------------------------------------
def test_o_comanda_reusita_lasa_o_linie_in_jurnal(caplog):
    """Botul loga doar eșecurile. Pentru un canal de control care poate bloca
    adrese, jumătatea reușită — cine, ce, când — nu exista nicăieri."""
    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _run(_ok, db=_DB(), text="/block 203.0.113.7 24h")

    lines = [r for r in caplog.records if r.getMessage() == "telegram command"]
    assert len(lines) == 1
    assert lines[0].chat_id == CHAT_ID
    assert lines[0].command == "/block 203.0.113.7 24h"
    assert lines[0].handler == "cmd_status"


def test_linia_de_succes_e_marginita(caplog):
    """Textul vine de la un client Telegram și nu e mărginit de nimic din codul
    ăsta. Sentinel e musafir pe gazdă, iar discul e al altcuiva."""
    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _run(_ok, db=_DB(), text="/mute " + "x" * 5000)

    line = next(r for r in caplog.records if r.getMessage() == "telegram command")
    assert len(line.command) <= 200


def test_o_comanda_picata_nu_se_logheaza_si_ca_reusita(caplog):
    """O comandă care a crăpat trebuie să apară o singură dată, ca eșec."""
    async def crapa(update, context):
        raise RuntimeError("boom")

    crapa.__name__ = "cmd_mute"

    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _run(crapa, db=_DB())

    assert not [r for r in caplog.records if r.getMessage() == "telegram command"]
    assert len([r for r in caplog.records
                if r.getMessage() == "telegram handler failed"]) == 1
