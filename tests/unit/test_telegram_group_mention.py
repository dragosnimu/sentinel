"""T4 din audit: un grup cu mai multe instanțe și un `/block` fără mențiune.

docs/TELEGRAM.md §8: mai multe instanțe Sentinel pot împărți un singur grup
Telegram, câte un bot fiecare — și fiecare bot citește din ACELAȘI fir de
mesaje. Un `/block 203.0.113.7` scris fără `@username` ajunge la toate
boturile deodată, care îl execută fiecare pe gazda ei: o singură comandă
tastată o dată blochează aceeași adresă pe două servere de producție.

Comenzile doar-citire nu trec prin gardă — răspund amândouă, dar informația
repetată e zgomot, nu o acțiune dublă. Decizia e documentată explicit în
§8, nu doar luată tăcut aici.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.telegram import bot  # noqa: E402


def run(c):
    return asyncio.run(c)


class _Msg:
    def __init__(self, text: str) -> None:
        self.text = text
        self.caption = None
        self.replies: list[str] = []

    async def reply_text(self, text, **_kw):
        self.replies.append(text)


def _update(chat_type: str, text: str):
    message = _Msg(text)
    chat = SimpleNamespace(id=1, type=chat_type)
    return SimpleNamespace(effective_chat=chat, effective_message=message,
                           message=message), message


def _context(username: str | None):
    return SimpleNamespace(bot=SimpleNamespace(username=username))


def test_a_bare_command_in_a_group_is_refused_with_a_hint():
    called = {"n": 0}

    async def handler(update, context):
        called["n"] += 1

    wrapped = bot._require_mention_in_group(handler, "block")
    update, message = _update("group", "/block 203.0.113.7")
    run(wrapped(update, _context("sentinel_host_a_bot")))

    assert called["n"] == 0, "comanda fără mențiune nu trebuia să execute nimic"
    assert message.replies, "trebuia să primească un indiciu"
    assert "@sentinel_host_a_bot" in message.replies[0]


def test_a_mentioned_command_in_a_group_runs():
    called = {"n": 0}

    async def handler(update, context):
        called["n"] += 1

    wrapped = bot._require_mention_in_group(handler, "block")
    update, message = _update("group", "/block@sentinel_host_a_bot 203.0.113.7")
    run(wrapped(update, _context("sentinel_host_a_bot")))

    assert called["n"] == 1
    assert message.replies == []


def test_mention_check_is_case_insensitive():
    """Telegram normalizeaza username-urile la scriere, dar un operator poate
    tasta orice capitalizare — gardă nu are voie sa refuze din cauza asta."""
    called = {"n": 0}

    async def handler(update, context):
        called["n"] += 1

    wrapped = bot._require_mention_in_group(handler, "block")
    update, message = _update("group", "/block@SENTINEL_HOST_A_BOT 203.0.113.7")
    run(wrapped(update, _context("sentinel_host_a_bot")))

    assert called["n"] == 1


def test_a_private_chat_never_needs_the_mention():
    """Un chat privat n-are cum să fie împărțit cu alt bot — cerința ar fi
    doar friecțiune fără niciun folos."""
    called = {"n": 0}

    async def handler(update, context):
        called["n"] += 1

    wrapped = bot._require_mention_in_group(handler, "block")
    update, message = _update("private", "/block 203.0.113.7")
    run(wrapped(update, _context("sentinel_host_a_bot")))

    assert called["n"] == 1
    assert message.replies == []


def test_a_mention_for_a_different_bot_is_still_refused():
    """Exact scenariul de la producere: `/block@sentinel_host_b_bot` scris
    într-un grup unde ambele boturi citesc — botul A nu trebuie să acționeze
    pe o comandă adresată explicit botului B."""
    called = {"n": 0}

    async def handler(update, context):
        called["n"] += 1

    wrapped = bot._require_mention_in_group(handler, "block")
    update, message = _update("group", "/block@sentinel_host_b_bot 203.0.113.7")
    run(wrapped(update, _context("sentinel_host_a_bot")))

    assert called["n"] == 0


def test_missing_bot_username_fails_open_not_closed():
    """Botul își cunoaște username-ul după `initialize()`, deci în producție
    n-ar trebui să lipsească niciodată la un update real — dar o gardă de
    comoditate care nu poate decide n-are voie să refuze o comandă legitimă."""
    called = {"n": 0}

    async def handler(update, context):
        called["n"] += 1

    wrapped = bot._require_mention_in_group(handler, "block")
    update, message = _update("group", "/block 203.0.113.7")
    run(wrapped(update, _context(None)))

    assert called["n"] == 1


def test_read_only_commands_are_not_wrapped_by_the_mention_guard():
    """`/status` (READ_ONLY) trebuie să rămână apelabil fără mențiune într-un
    grup — decizia documentată în §8: comenzile doar-citire răspund la toate
    instanțele, comenzile care schimbă starea nu."""
    from sentinel.telegram.bot import READ_ONLY, ACTING

    read_only_names = {n for c in READ_ONLY for n in c.names}
    acting_names = {n for c in ACTING for n in c.names}
    assert "status" in read_only_names
    assert "block" in acting_names
    assert not (read_only_names & acting_names), "un nume nu poate fi în ambele tabele"


def _fake_secrets():
    return SimpleNamespace(require=lambda k: "0:test",
                           has=lambda k: True, get=lambda k, d=None: None)


def _closure_freevar_names(callback) -> set[str]:
    """Toate numele de variabile închise, pe tot lanțul de wrappere.

    `_guard(handler)` închide DOAR `handler`. `_require_mention_in_group(handler,
    name)` închide și `handler`, ȘI `name` — deci `"name"` apare undeva în lanț
    dacă și numai dacă gardă de mențiune a fost aplicată. Citit din
    `__closure__`/`co_freevars`, nu presupus din care buclă a înregistrat
    comanda: exact ce ar rula, nu ce credea cineva că înregistrează.
    """
    names: set[str] = set()
    node = callback
    seen: set[int] = set()
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if not getattr(node, "__closure__", None):
            break
        names.update(node.__code__.co_freevars)
        cells = dict(zip(node.__code__.co_freevars, node.__closure__))
        nxt = cells.get("handler")
        node = nxt.cell_contents if nxt is not None else None
    return names


def test_the_built_application_wraps_acting_but_not_read_only():
    """Verificarea autoritară: în APLICAȚIA REALĂ construită de
    `build_application`, handler-ul înregistrat pentru o comandă ACTING
    trebuie să aibă `_require_mention_in_group` undeva în lanțul lui de
    închideri, iar unul pentru o comandă READ_ONLY nu."""
    from telegram.ext import CommandHandler

    from sentinel.config import Config
    from sentinel.telegram import bot as bot_mod

    app = bot_mod.build_application(Config(), _fake_secrets())

    by_command: dict[str, object] = {}
    for handlers in app.handlers.values():
        for h in handlers:
            if isinstance(h, CommandHandler):
                for cmd in h.commands:
                    by_command[cmd] = h.callback

    assert "name" in _closure_freevar_names(by_command["block"]), (
        "/block nu pare înfășurat de _require_mention_in_group")
    assert "name" not in _closure_freevar_names(by_command["status"]), (
        "/status NU trebuia să treacă prin gardă de mențiune (§8: doar-citire)")
