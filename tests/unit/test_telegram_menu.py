"""Comenzile botului trebuie să existe ȘI în Telegram, nu doar în cod.

Pe gazdă, `getMyCommands` întorcea listă goală de când există botul: 23 de
comenzi înregistrate, meniu inexistent, autocomplete inexistent, butonul de
comenzi gol. `post_init` conecta baza, pornea bucla de push și scria „telegram
bot ready" — fără să fi cerut vreodată publicarea listei.

Ce a costat: operatorul a raportat „comanda selfcheck nu e funcțională". Comanda
exista, era înregistrată și răspundea; ce nu exista era orice urmă a ei în
interfață. Un instrument de urgență ale cărui comenzi nu se văd nu e un
instrument pe care îl poți folosi la 3 dimineața.

Testele de aici construiesc **aplicația reală** cu `build_application` și rulează
`post_init`-ul ei real. O reimplementare a înregistrării ar fi verificat ce am
scris în test, nu ce pornește pe server — exact confuzia dintre intenție și
efect care a produs defectul.

Ce NU se poate verifica de aici: că Telegram acceptă forma cerută de API. Nu
există token în suită, deci `setMyCommands` nu e chemat niciodată cu adevărat.
Ce se poate verifica local — și e verificat mai jos — sunt limitele publicate de
API și impuse de bibliotecă: nume `[a-z0-9_]{1,32}`, descriere 1..256, cel mult
100 de comenzi.
"""
from __future__ import annotations

import asyncio
import logging
import re
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from telegram import BotCommand  # noqa: E402
from telegram.constants import BotCommandLimit  # noqa: E402
from telegram.error import RetryAfter  # noqa: E402
from telegram.ext import ExtBot  # noqa: E402

from sentinel.config import Config  # noqa: E402
from sentinel.telegram import bot  # noqa: E402

# Substituent, nu id-ul operatorului: depozitul e public. Vezi nota din
# tests/unit/test_telegram_errors.py — Telegram nu are un interval rezervat
# pentru exemple, iar nimic din teste nu trimite nimic către valoarea asta.
CHAT_ID = 1234567890

VALID_NAME = re.compile(r"^[a-z0-9_]{1,32}$")


def _secrets():
    """Token deliberat fără formă de token: garda de sanitizare a depozitului
    respinge, corect, orice șir care arată a credențial real."""
    return SimpleNamespace(require=lambda k: "0:test", has=lambda k: True,
                           get=lambda k, d=None: None)


def _cfg(chat_ids=(CHAT_ID,)) -> Config:
    cfg = Config()
    cfg.telegram.allowed_chat_ids = list(chat_ids)
    return cfg


class _FakeDB:
    """Cât din `Database` atinge `post_init` și prima tură a buclei de push."""

    def __init__(self) -> None:
        self.connected = False
        self.closed = False

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.closed = True

    async def fetch(self, *_a, **_kw):
        return []

    async def fetchrow(self, *_a, **_kw):
        return None

    async def fetchval(self, *_a, **_kw):
        return None

    async def execute(self, *_a, **_kw):
        return None


class _Telegram:
    """Ce a primit Telegram, și ce răspunde înapoi.

    `stored` e ce ar avea Telegram după apel — de asta `get_my_commands`
    citește din el și nu din ce s-a cerut. Testul care simulează „a acceptat
    cererea și n-a reținut nimic" schimbă exact asta.
    """

    def __init__(self, *, set_error=None, get_error=None, store=True) -> None:
        self.sent: list[tuple[int, tuple[BotCommand, ...]]] = []
        self.stored: dict[int, tuple[BotCommand, ...]] = {}
        self.set_error = set_error
        self.get_error = get_error
        self.store = store
        self.extra: BotCommand | None = None
        # Telegram reține numele, dar altă descriere decât cea trimisă.
        self.drift: str | None = None
        # Ce era gata în `bot_data` în clipa în care s-a vorbit cu Telegram.
        # `_start` pune aici aplicația; vezi testul de ordine din `post_init`.
        self.app = None
        self.ready_at_publish: list[set[str]] = []

    @staticmethod
    def _chat_id(scope) -> int:
        assert scope is not None, (
            "publicat în scope-ul implicit: meniul ar fi vizibil oricui știe "
            "numele botului, iar fișierul promite tăcere pentru chat-urile "
            "neautorizate")
        return scope.chat_id

    async def set_my_commands(self, commands, scope=None, **_kw):
        chat_id = self._chat_id(scope)
        if self.app is not None:
            self.ready_at_publish.append(set(self.app.bot_data))
        if self.set_error is not None:
            raise self.set_error
        self.sent.append((chat_id, tuple(commands)))
        if self.store:
            kept = tuple(BotCommand(c.command, self.drift or c.description)
                         for c in commands)
            self.stored[chat_id] = kept + (
                (self.extra,) if self.extra is not None else ())
        return True

    async def get_my_commands(self, scope=None, **_kw):
        chat_id = self._chat_id(scope)
        if self.get_error is not None:
            raise self.get_error
        return self.stored.get(chat_id, ())


@pytest.fixture
def telegram(monkeypatch):
    """Interceptează cele două apeluri pe CLASA botului.

    `Bot` are `__slots__`, deci nu se poate pune un atribut pe instanță; iar
    instanța trebuie să rămână cea reală, construită de `build_application`.
    """
    fake = _Telegram()

    async def set_my_commands(self, commands, scope=None, **kw):
        return await fake.set_my_commands(commands, scope=scope, **kw)

    async def get_my_commands(self, scope=None, **kw):
        return await fake.get_my_commands(scope=scope, **kw)

    monkeypatch.setattr(ExtBot, "set_my_commands", set_my_commands)
    monkeypatch.setattr(ExtBot, "get_my_commands", get_my_commands)
    return fake


def _start(cfg: Config, monkeypatch, watch: _Telegram | None = None) -> tuple[object, _FakeDB]:
    """Construiește aplicația reală și rulează `post_init`-ul ei real."""
    db = _FakeDB()
    monkeypatch.setattr(bot, "Database", lambda _cfg: db)
    app = bot.build_application(cfg, _secrets())
    if watch is not None:
        watch.app = app

    async def main():
        await app.post_init(app)
        task = app.bot_data.get("push_task")
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(main())
    return app, db


# --- 1. lista ajunge la Telegram -------------------------------------------
def test_pornirea_publica_lista_de_comenzi(telegram, monkeypatch):
    """Defectul, exact: botul pornea fără să ceară vreodată publicarea.

    Dacă `post_init` nu cheamă `setMyCommands`, operatorul nu are meniu, nu are
    autocomplete și nu are cum să afle ce comenzi există decât citind codul.
    """
    _start(_cfg(), monkeypatch)

    assert telegram.sent, "post_init nu a cerut niciodată publicarea comenzilor"
    chat_id, sent = telegram.sent[0]
    assert chat_id == CHAT_ID
    assert {c.command for c in sent} == {c.command for c in bot.menu_commands()}
    assert all(c.description.strip() for c in sent)


def test_fiecare_chat_permis_isi_primeste_meniul(telegram, monkeypatch):
    """Al doilea operator nu trebuie să rămână fără meniu fiindcă e al doilea."""
    second = CHAT_ID + 1
    _start(_cfg((CHAT_ID, second)), monkeypatch)

    assert {chat for chat, _ in telegram.sent} == {CHAT_ID, second}


# --- 2. lista publicată = handlerele înregistrate ---------------------------
def test_meniul_acopera_fiecare_comanda_inregistrata(monkeypatch):
    """O comandă adăugată în cod și nepublicată face testul roșu.

    Asta e apărarea împotriva cauzei, nu a simptomului: defectul n-a fost o
    listă greșită, ci o listă care nu exista. Orice nume care ajunge la un
    `CommandHandler` trebuie să vină din tabelul din care se derivă meniul —
    altfel comanda funcționează și rămâne invizibilă, ceea ce e chiar starea de
    dinaintea acestei schimbări.
    """
    db = _FakeDB()
    monkeypatch.setattr(bot, "Database", lambda _cfg: db)
    app = bot.build_application(_cfg(), _secrets())

    registered = {name for hs in app.handlers.values() for h in hs
                  for name in getattr(h, "commands", ())}
    from_table = {n for c in bot.COMMANDS for n in c.names}
    published = {c.command for c in bot.menu_commands()}

    assert registered, "nu s-a înregistrat nicio comandă"
    assert registered == from_table, (
        "comenzi înregistrate pe lângă tabel (deci nepublicate): "
        f"{sorted(registered - from_table)}")
    assert published <= registered, (
        "meniul anunță comenzi care nu răspund: "
        f"{sorted(published - registered)}")
    # Fiecare comandă are exact un nume în meniu, și acela e unul care răspunde.
    for command in bot.COMMANDS:
        in_menu = [n for n in command.names if n in published]
        assert in_menu == [command.canonical], (
            f"{command.names} publică {in_menu}, nu doar numele canonic")


def test_meniul_nu_publica_aliasuri(monkeypatch):
    """Un meniu cu `blocklist` și `blocate` și `expuneri` și `exposures` e
    zgomot. Aliasurile rămân funcționale — testul de mai sus le cere
    înregistrate — dar nu se văd."""
    published = {c.command for c in bot.menu_commands()}
    aliases = {n for c in bot.COMMANDS for n in c.names[1:]}

    assert not (published & aliases), f"aliasuri în meniu: {sorted(published & aliases)}"
    assert len(published) == len(bot.COMMANDS)


# Textele din care se citește ce nume îi spune botul operatorului să tasteze.
# Doar căile pe care ies mesaje în chat: pachetul Telegram, plus generatorul de
# alerte al autoverificării, care tipărește `/selfcheck`. Deliberat NU tot
# `sentinel/`: rutele web conțin căi ca „/health", iar o cale HTTP nu e un nume
# pe care operatorul îl tastează în Telegram.
_SOURCES = ["sentinel/telegram/bot.py", "sentinel/telegram/views.py",
            "sentinel/telegram/patch_flow.py", "sentinel/telegram/quiet.py",
            "sentinel/telegram/bot_ttl.py", "sentinel/selfcheck/runner.py"]

_SLASH = re.compile(r"/([a-z][a-z0-9_]{0,31})")


def _printed_names() -> set[str]:
    """Numele de comenzi care apar în șiruri pe care botul chiar le trimite.

    Citite din AST, cu docstring-urile EXCLUSE. Un docstring e un șir ca oricare
    altul pentru o expresie regulată peste text, dar nu ajunge la nimeni — iar
    docstring-ul lui `Command` din `bot.py` menționează chiar `/ajutor` și
    `/status`. Dacă ar fi numărate, testul și-ar confirma singur criteriul din
    comentariile scrise ca să-l explice.
    """
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    found: set[str] = set()
    for rel in _SOURCES:
        tree = ast.parse((root / rel).read_text(encoding="utf-8"))
        docstrings = {id(n.value) for n in ast.walk(tree)
                      if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docstrings):
                found |= set(_SLASH.findall(node.value))
    return found


def _help_names() -> set[str]:
    """Toate numele din `views.HELP`, nu doar primul de pe fiecare rând.

    Rândul `/rezolva <id> · /fp <id>` poartă două comenzi. O versiune care lua
    `line.split()[0]` nu vedea niciodată `/fp` — adică exact jumătate dintr-un
    rând, tăcut.
    """
    from sentinel.telegram import views

    names: set[str] = set()
    for line in views.HELP.splitlines():
        if line.startswith("/"):
            names |= set(_SLASH.findall(line))
    return names


# Grupuri pentru care criteriul TACE: niciun text al botului nu tipărește vreunul
# dintre numele lor, deci nu există nimic din care numele canonic să fie derivat.
# Enumerate aici pe față, nu sărite tăcut — o comandă nouă despre care botul nu
# spune nicăieri nimic trebuie să apară în conversație, nu să treacă neobservată.
#
# `comportament`: ales fiindcă e numele românesc, iar docstring-ul comenzii și
# interfața sunt în română; `behaviour` și `profil` sunt aliasuri despre care
# operatorul nu e informat nicăieri.
UNPRINTED = {"comportament"}


def test_numele_canonic_e_cel_pe_care_il_tipareste_botul():
    """Criteriul ales, FIXAT: numele din meniu e cel pe care textele botului îi
    spun operatorului să-l tasteze.

    Versiunea anterioară a acestui test nu putea pica: cerea `canonical in
    published`, iar `menu_commands()` publică prin construcție exact `canonical`
    — adevărat pentru orice tabel, inclusiv unul cu toate tuplurile inversate.
    Un verificator a inversat 13 rânduri (`("incidente","incidents")` →
    `("incidents","incidente")` și celelalte) și suita a rămas verde, cu meniul
    anunțând `/incidents` în timp ce ajutorul trimite la `/incidente`.

    Ce se verifică acum: numele așteptat se derivă din chiar textele botului, iar
    grupul trebuie să publice ACEL nume, nu „un nume". `views.HELP` e autoritatea
    unde spune ceva — e lista pe care operatorul o citește prima.

    Unde botul tipărește DOUĂ nume pentru același grup (`/patches` și
    `/patch <id>`, `/rezolva` și `/resolve`), criteriul nu le desparte, și testul
    nu se preface că o face: cere doar ca numele canonic să fie unul dintre ele.
    """
    printed = _printed_names()
    from_help = _help_names()

    assert len(from_help) >= 15, "textul de ajutor nu mai listează comenzi"
    assert "fp" in from_help, "extragerea din HELP a pierdut al doilea nume de pe rând"
    assert {"expuneri", "stiu", "ajutor"} <= printed, \
        "citirea textelor botului nu mai vede numele tipărite în răspunsuri"

    silent: set[str] = set()
    for command in bot.COMMANDS:
        names = set(command.names)
        in_help = from_help & names
        in_text = printed & names
        if in_help:
            assert command.canonical in in_help, (
                f"meniul publică /{command.canonical}, iar textul de ajutor trimite "
                f"la {sorted('/' + n for n in in_help)} — același lucru, două nume")
        elif in_text:
            assert command.canonical in in_text, (
                f"meniul publică /{command.canonical}, iar botul tipărește "
                f"{sorted('/' + n for n in in_text)}")
        else:
            silent.add(command.canonical)

    assert silent == UNPRINTED, (
        "s-a schimbat mulțimea comenzilor despre care botul nu spune nicăieri "
        f"nimic: {sorted(silent)} față de {sorted(UNPRINTED)}")


# --- 3. limitele API-ului ---------------------------------------------------
def test_meniul_respecta_limitele_telegram():
    """Telegram refuză întregul apel dacă o singură intrare e invalidă, deci o
    descriere goală sau un nume cu diacritic nu strică o comandă — le ascunde pe
    toate 23."""
    commands = bot.menu_commands()

    assert 0 < len(commands) <= BotCommandLimit.MAX_COMMAND_NUMBER
    assert len({c.command for c in commands}) == len(commands), "nume duplicat"
    for c in commands:
        assert VALID_NAME.match(c.command), f"nume respins de Telegram: {c.command!r}"
        assert BotCommandLimit.MIN_COMMAND <= len(c.command) <= BotCommandLimit.MAX_COMMAND
        assert c.description.strip(), f"/{c.command} fără descriere"
        assert len(c.description) <= BotCommandLimit.MAX_DESCRIPTION, \
            f"/{c.command}: descriere de {len(c.description)} caractere"


def test_descrierile_sunt_in_romana():
    """Meniul e text de interfață, iar interfața e în română. O descriere în
    engleză într-un meniu românesc e o scăpare vizibilă operatorului."""
    commands = bot.menu_commands()
    romanian = sum(1 for c in commands
                   if re.search(r"[ăâîșşțţ]", c.description, re.I))
    # Nu fiecare descriere are diacritice („O linie: incidente deschise și
    # servicii" are, „Planuri de patch în așteptare" are), dar dacă lista ar fi
    # scrisă în engleză numărul ar cădea la zero.
    assert romanian >= len(commands) // 2, (
        f"doar {romanian} din {len(commands)} descrieri arată a română")
    for c in commands:
        assert not re.match(r"^(list|show|the|get|open|display) ", c.description, re.I), \
            f"/{c.command}: descriere în engleză — {c.description!r}"


# --- 4. eșecul publicării nu oprește botul ----------------------------------
def test_o_eroare_la_publicare_nu_impiedica_pornirea(telegram, monkeypatch, caplog):
    """Canalul de alertare e mai important decât meniul.

    Dacă `setMyCommands` pică (rate limit, rețea), botul trebuie să pornească
    oricum: baza conectată, bucla de push pornită. O excepție lăsată să iasă din
    `post_init` oprește `Application.initialize()`, deci systemd repornește la
    nesfârșit — adică fix avaria de 24 de ore, cu altă cauză.
    """
    telegram.set_error = RetryAfter(30)

    with caplog.at_level(logging.WARNING, logger="sentinel.telegram.bot"):
        app, db = _start(_cfg(), monkeypatch)

    assert db.connected, "baza nu s-a conectat"
    assert app.bot_data.get("db") is db
    assert app.bot_data.get("push_task") is not None, "bucla de push nu a pornit"

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "eșecul publicării a fost înghițit — nicio urmă în jurnal"
    detail = " ".join(f"{r.getMessage()} {getattr(r, 'detail', '')}" for r in warnings)
    assert "menu" in detail and "RetryAfter" in detail, detail


def test_un_esec_la_publicare_nu_e_raportat_ca_reusita(telegram, monkeypatch, caplog):
    """Nu doar „nu moare": nu are voie nici să pară că a mers."""
    telegram.set_error = RetryAfter(30)

    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _start(_cfg(), monkeypatch)

    assert not [r for r in caplog.records
                if r.getMessage() == "command menu published"], \
        "a raportat meniul ca publicat deși apelul a picat"


def test_publicarea_se_confirma_citind_inapoi(telegram, monkeypatch, caplog):
    """Un cod de ieșire nu e dovadă de efect.

    `setMyCommands` întoarce True fiindcă cererea a fost acceptată. Aici
    Telegram acceptă și nu reține nimic — exact forma pe care operatorul a
    găsit-o pe producție, cu `getMyCommands` gol. Dacă nu se citește înapoi,
    jurnalul spune „published" peste un meniu care nu există.
    """
    telegram.store = False           # acceptă, dar nu reține

    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _start(_cfg(), monkeypatch)

    assert telegram.sent, "nici măcar nu s-a încercat publicarea"
    assert not [r for r in caplog.records if r.getMessage() == "command menu published"], \
        "a raportat succes fără să verifice că Telegram chiar are lista"
    assert [r for r in caplog.records
            if r.getMessage() == "command menu is not what was sent"], \
        "diferența dintre ce s-a trimis și ce are Telegram nu s-a văzut nicăieri"


def test_o_comanda_in_plus_la_telegram_nu_trece_drept_succes(telegram, monkeypatch, caplog):
    """Verificarea e egalitate, nu incluziune.

    Dacă Telegram ține o comandă pentru care nu mai există handler, meniul îi
    oferă operatorului ceva ce nu răspunde niciodată — adică exact simptomul
    raportat („comanda X nu e funcțională"), pe dos.
    """
    telegram.extra = BotCommand("vechi", "o comandă care nu mai există")

    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _start(_cfg(), monkeypatch)

    messages = [r.getMessage() for r in caplog.records]
    assert "command menu published" not in messages
    line = next(r for r in caplog.records
                if r.getMessage() == "command menu is not what was sent")
    assert line.unexpected == "vechi"
    assert line.missing == ""


def test_o_descriere_schimbata_nu_trece_drept_succes(telegram, monkeypatch, caplog):
    """Cealaltă jumătate a citirii înapoi.

    Comparația e pe perechea (nume, descriere). Dacă s-ar compara doar numele,
    un meniu cu toate descrierile greșite — de pildă rămase de la o versiune
    veche, fiindcă apelul de actualizare a fost respins — ar fi raportat ca
    publicat corect, iar operatorul ar citi în telefon altceva decât spune codul.
    """
    telegram.drift = "descriere veche"

    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _start(_cfg(), monkeypatch)

    messages = [r.getMessage() for r in caplog.records]
    assert "command menu published" not in messages
    line = next(r for r in caplog.records
                if r.getMessage() == "command menu is not what was sent")
    # Același nume de comandă apare de ambele părți: numele e acolo, textul nu.
    assert "ajutor" in line.missing and "ajutor" in line.unexpected


def test_meniul_se_publica_dupa_ce_bucla_de_push_ruleaza(telegram, monkeypatch):
    """Ordinea din `post_init`, ca proprietate, nu ca afirmație în comentariu.

    Publicarea vorbește cu Telegram și poate sta pe timeout-urile bibliotecii.
    Dacă s-ar face înaintea pornirii buclei de push, prima alertă a zilei ar
    aștepta după un meniu — exact inversul priorității pe care fișierul o
    declară peste tot.
    """
    _start(_cfg(), monkeypatch, telegram)

    assert telegram.ready_at_publish, "nu s-a ajuns la publicare"
    ready = telegram.ready_at_publish[0]
    assert "push_task" in ready, \
        "meniul se publică înainte ca bucla de push să existe"
    assert {"db", "cfg"} <= ready


def test_o_confirmare_imposibila_nu_trece_drept_succes(telegram, monkeypatch, caplog):
    """„Necunoscut" și „în regulă" sunt stări diferite.

    Dacă citirea înapoi pică, nu știm dacă meniul e acolo. Asta se spune; nu se
    rotunjește la succes și nici la eșec.
    """
    telegram.get_error = RetryAfter(30)

    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _start(_cfg(), monkeypatch)

    messages = [r.getMessage() for r in caplog.records]
    assert "command menu published" not in messages
    assert "command menu sent but not confirmed" in messages


def test_publicarea_confirmata_se_logheaza(telegram, monkeypatch, caplog):
    """Reversul: dacă totul merge, trebuie să existe linia care o spune —
    altfel diagnosticul următor începe iar de la zero."""
    with caplog.at_level(logging.INFO, logger="sentinel.telegram.bot"):
        _start(_cfg(), monkeypatch)

    published = [r for r in caplog.records if r.getMessage() == "command menu published"]
    assert len(published) == 1
    assert published[0].chats == 1
    assert published[0].commands == len(bot.menu_commands())


def test_fara_niciun_chat_permis_se_spune(telegram, monkeypatch, caplog):
    """Zero chat-uri permise înseamnă zero publicări. Tăcerea ar fi
    indistinctă de o publicare reușită."""
    with caplog.at_level(logging.WARNING, logger="sentinel.telegram.bot"):
        _start(_cfg(()), monkeypatch)

    assert not telegram.sent
    assert any("no allowed chat" in r.getMessage() for r in caplog.records)
