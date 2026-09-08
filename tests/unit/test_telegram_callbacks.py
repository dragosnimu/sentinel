"""`on_callback` prin handlerul REAL, nu doar prin `callback_sign` izolat.

T2 din audit: `bot.py:789` făcea `_, ip, ttl_s = data.split(":", 2)` pe un
`blk:` cu adresa în text — pe orice IPv6 (care are propriile lui două
puncte), asta arunca `ValueError` NECONTROLAT, iar tap-ul operatorului nu
producea nimic: nici bloc, nici mesaj, nici linie de jurnal. Rescrierea
codează adresa binar (vezi `callback_sign.py`), ceea ce elimină problema la
rădăcină — dar testele astea verifică EFECTUL prin handlerul chiar înregistrat,
nu presupunerea că noul format „ar trebui" să meargă.

Verifică și restul lui T2/T6: un buton expirat sau falsificat nu are voie să
acționeze, și o excepție neașteptată în `on_callback` trebuie să ajungă la
operator ca o alertă pe buton, nu ca o tăcere.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.telegram import bot, callback_sign  # noqa: E402

KEY = b"test-fixture-hmac-key"
CHAT_ID = 700000001


class _StubQuery:
    def __init__(self, data: str) -> None:
        self.data = data
        self.edits: list[str] = []
        self.answers: list[tuple] = []

    async def answer(self, *a, **kw):
        self.answers.append((a, kw))

    async def edit_message_text(self, text, **_kw):
        self.edits.append(text)


def _cfg():
    return SimpleNamespace(telegram=SimpleNamespace(
        allowed_chat_ids=[CHAT_ID], allowed_user_ids=[], owner_chat_id=CHAT_ID,
        operator_chat_ids=[], callback_ttl_s=600))


def _update(query: _StubQuery):
    return SimpleNamespace(callback_query=query,
                           effective_chat=SimpleNamespace(id=CHAT_ID, type="private"),
                           effective_user=SimpleNamespace(id=CHAT_ID))


def _context(cfg, db):
    return SimpleNamespace(bot_data={"cfg": cfg, "db": db, "callback_hmac_key": KEY})


def run(c):
    return asyncio.run(c)


# --- cmd_block: validari necesare pentru ca semnarea sa nu explodeze ------
class _CmdMsg:
    def __init__(self, args: list[str]) -> None:
        self.args = args
        self.replies: list = []

    async def reply_text(self, text, **kw):
        self.replies.append((text, kw))


def _cmd_context(cfg, args):
    msg = _CmdMsg(args)
    update = SimpleNamespace(effective_chat=SimpleNamespace(id=CHAT_ID),
                             message=msg)
    context = SimpleNamespace(args=args, bot_data={"cfg": cfg, "callback_hmac_key": KEY})
    return update, context, msg


def test_cmd_block_refuses_an_invalid_ip_before_signing():
    update, context, msg = _cmd_context(_cfg(), ["not-an-ip", "1h"])
    run(bot.cmd_block(update, context))
    assert "nu e o adresă IP validă" in msg.replies[0][0]


def test_cmd_block_refuses_a_ttl_below_the_minimum():
    update, context, msg = _cmd_context(_cfg(), ["203.0.113.7", "30"])  # 30s < 60s
    run(bot.cmd_block(update, context))
    assert "60s" in msg.replies[0][0] or "30 de zile" in msg.replies[0][0]


def test_cmd_block_refuses_a_ttl_above_the_thirty_day_maximum():
    too_long = str(bot.MAX_BLOCK_TTL_S + 3600)
    update, context, msg = _cmd_context(_cfg(), ["203.0.113.7", too_long])
    run(bot.cmd_block(update, context))
    assert "30 de zile" in msg.replies[0][0]


def test_cmd_block_accepts_a_valid_ttl_and_signs_the_button():
    update, context, msg = _cmd_context(_cfg(), ["203.0.113.7", "1h"])
    run(bot.cmd_block(update, context))
    assert len(msg.replies) == 1
    text, kw = msg.replies[0]
    kb = kw["reply_markup"]
    data = kb.inline_keyboard[0][0].callback_data
    ip, ttl, ref, _ = callback_sign.verify_ip_action(data, KEY, ttl_s=600)
    assert (ip, ttl, ref) == ("203.0.113.7", 3600, 0)


def test_cmd_block_accepts_permanent():
    update, context, msg = _cmd_context(_cfg(), ["203.0.113.7", "perm"])
    run(bot.cmd_block(update, context))
    text, kw = msg.replies[0]
    data = kw["reply_markup"].inline_keyboard[0][0].callback_data
    ip, ttl, ref, _ = callback_sign.verify_ip_action(data, KEY, ttl_s=600)
    assert (ip, ttl) == ("203.0.113.7", 0)


# --- IPv6 prin handlerul real ------------------------------------------------
def test_blk_with_an_ipv6_actor_blocks_through_the_real_handler(monkeypatch):
    """Falsificat: cu vechiul `data.split(':', 2)`, un `blk:2001:db8::1:...`
    ar fi crăpat cu `ValueError` — vezi falsificarea din raportul agentului."""
    called = {}

    async def _block(db, ip, *, ttl, reason, by):
        called["ip"] = ip
        called["ttl"] = ttl
        return {}

    monkeypatch.setattr(bot.actions, "block", _block)

    data = callback_sign.sign_ip_action("blk", KEY, "2001:db8::1", 3600,
                                        ref=5, issued_at=int(time.time()))
    query = _StubQuery(data)
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert called["ip"] == "2001:db8::1"
    assert called["ttl"] == 3600
    assert query.edits == ["🛡️ Blocat <code>2001:db8::1</code>."]


def test_unblk_with_an_ipv6_actor_through_the_real_handler(monkeypatch):
    called = {}

    async def _unblock(db, ip, *, by):
        called["ip"] = ip
        return {}

    monkeypatch.setattr(bot.actions, "unblock", _unblock)

    data = callback_sign.sign_ip_action("unblk", KEY, "2001:db8::1", 0,
                                        issued_at=int(time.time()))
    query = _StubQuery(data)
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert called["ip"] == "2001:db8::1"
    assert query.edits == ["↩️ Deblocat <code>2001:db8::1</code>."]


# --- nteu: „Nu sunt eu", prin handlerul real -------------------------------
# Ship-note: butonul era trimis ca text simplu (`nteu:<id secvențial>`), fără
# nicio semnătură — orice membru `_can_act` al chatului putea trimite manual
# `nteu:<orice id>` și `on_callback` executa `block_and_terminate` pe orice
# sesiune ghicită, inclusiv una de pe o adresă din allowlist, unde efectul e
# să-ți închizi singur propriul SSH. Semnat acum ca blk:/unblk:.
class _NteuDB:
    """Verifică și CE id a fost interogat, nu doar că s-a interogat ceva —
    altfel un `session_id` extras greșit din payload (de exemplu, garbage
    dintr-o despachetare stricată) tot ar găsi rândul fixat aici, iar testul
    n-ar mai dovedi că handlerul a citit id-ul chiar din semnătură."""

    def __init__(self, row, expected_id: int) -> None:
        self._row = row
        self._expected_id = expected_id

    async def fetchrow(self, sql, session_id):
        assert session_id == self._expected_id, (
            f"interogat id={session_id!r}, așteptam {self._expected_id!r} — "
            f"id-ul sesiunii nu a fost extras corect din payload-ul semnat")
        return self._row


def test_nteu_with_a_signed_button_blocks_and_terminates_through_the_real_handler(monkeypatch):
    called = {}

    async def _block_and_terminate(db, ip, session_key, *, by, reason):
        called["ip"] = ip
        called["session_key"] = session_key
        return {"allowlisted": False, "blocked": True, "terminated": True}

    monkeypatch.setattr(bot.actions, "block_and_terminate", _block_and_terminate)

    data = callback_sign.sign_session_action(KEY, 77, issued_at=int(time.time()))
    query = _StubQuery(data)
    db = _NteuDB({"session_key": "s-77", "ip": "203.0.113.7",
                 "username": "op", "closed_at": None}, expected_id=77)
    run(bot.on_callback(_update(query), _context(_cfg(), db=db)))

    assert called["ip"] == "203.0.113.7"
    assert called["session_key"] == "s-77"
    assert "Blocat" in query.edits[0]


def test_an_expired_nteu_button_is_refused_and_does_not_act(monkeypatch):
    """Falsificat: TTL-ul de aici e `bot.NTEU_TTL_S` (7 zile), nu implicitul
    scurt al lui `blk:` — un buton de acum 10 zile tot trebuie respins."""
    async def _boom(*_a, **_kw):
        raise AssertionError(
            "block_and_terminate nu trebuia chemat pentru un buton expirat")

    monkeypatch.setattr(bot.actions, "block_and_terminate", _boom)

    old = int(time.time()) - 10 * 86_400
    data = callback_sign.sign_session_action(KEY, 77, issued_at=old)
    query = _StubQuery(data)
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert query.edits == ["⛔ Buton expirat."]


def test_a_tampered_nteu_button_is_refused_and_does_not_act(monkeypatch):
    """Exact atacul pe care semnătura există să-l oprească: cineva schimbă
    id-ul sesiunii, sperând să termine o sesiune arbitrară."""
    async def _boom(*_a, **_kw):
        raise AssertionError(
            "block_and_terminate nu trebuia chemat pentru un payload falsificat")

    monkeypatch.setattr(bot.actions, "block_and_terminate", _boom)

    data = callback_sign.sign_session_action(KEY, 77, issued_at=int(time.time()))
    tampered = data[:-1] + ("a" if data[-1] != "a" else "b")
    query = _StubQuery(tampered)
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert query.edits == ["⛔ Buton nevalid sau modificat."]


def test_the_old_unsigned_nteu_format_is_refused_not_executed(monkeypatch):
    """Un buton `nteu:<id>` fără semnătură — cum trimitea o instalare de
    dinaintea acestei livrări — trebuie respins la verificare, nu executat ca
    și cum ar fi semnat (vezi docs/TELEGRAM.md §5.1: butoanele vechi mor)."""
    async def _boom(*_a, **_kw):
        raise AssertionError(
            "nu trebuia executat un buton din formatul vechi, nesemnat")

    monkeypatch.setattr(bot.actions, "block_and_terminate", _boom)

    query = _StubQuery("nteu:77")
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert query.edits == ["⛔ Buton nevalid sau modificat."]


# --- expirare -----------------------------------------------------------
def test_an_expired_block_button_is_refused_and_does_not_act(monkeypatch):
    async def _boom(*_a, **_kw):
        raise AssertionError("actions.block nu trebuia chemat pentru un buton expirat")

    monkeypatch.setattr(bot.actions, "block", _boom)

    old = int(time.time()) - 10_000
    data = callback_sign.sign_ip_action("blk", KEY, "203.0.113.7", 3600, issued_at=old)
    query = _StubQuery(data)
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert query.edits == ["⛔ Buton expirat, folosește /block."]


def test_an_expired_unblock_button_hints_the_right_command(monkeypatch):
    async def _boom(*_a, **_kw):
        raise AssertionError("actions.unblock nu trebuia chemat pentru un buton expirat")

    monkeypatch.setattr(bot.actions, "unblock", _boom)

    old = int(time.time()) - 10_000
    data = callback_sign.sign_ip_action("unblk", KEY, "203.0.113.7", 0, issued_at=old)
    query = _StubQuery(data)
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert query.edits == ["⛔ Buton expirat, folosește /unblock."]


# --- falsificare directă -------------------------------------------------
def test_a_tampered_button_is_refused_and_does_not_act(monkeypatch):
    """Exact atacul pe care T6 îl documentează: un membru autorizat al
    chatului construiește manual un `callback_data` pentru o adresă pe care
    botul n-a oferit-o niciodată."""
    async def _boom(*_a, **_kw):
        raise AssertionError("actions.block nu trebuia chemat pentru un payload falsificat")

    monkeypatch.setattr(bot.actions, "block", _boom)

    data = callback_sign.sign_ip_action("blk", KEY, "203.0.113.7", 3600,
                                        issued_at=int(time.time()))
    tampered = data[:-1] + ("a" if data[-1] != "a" else "b")
    query = _StubQuery(tampered)
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert query.edits == ["⛔ Buton nevalid sau modificat."]


# --- T3-3: un `blk:` cu un câmp non-ASCII e refuzat, nu scapă neprins ------
def test_a_non_ascii_blk_field_is_refused_not_an_uncaught_exception(monkeypatch):
    """`_verified` (`callback_sign.py`) ridică `Malformed` — o subclasă de
    `CallbackError`, NU `BadSignature` — pentru un câmp în afara ASCII.
    `on_callback` prinde `callback_sign.CallbackError`, nu doar
    `BadSignature`: dacă cineva ar restrânge acel `except` la `BadSignature`
    (crezând-o mai precisă), exact acest payload ar scăpa neprins prin
    `on_callback`, iar tap-ul operatorului ar rămâne pe un spinner fără
    niciun răspuns și fără nicio linie de jurnal utilă — plasa
    `_guard_callback` tot l-ar prinde, dar operatorul ar vedea eroarea
    generică de-acolo, nu „buton nevalid"."""
    async def _boom(*_a, **_kw):
        raise AssertionError("actions.block nu trebuia chemat pentru un payload nevalid")

    monkeypatch.setattr(bot.actions, "block", _boom)

    query = _StubQuery("blk:é:0:0:0:x")
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert query.edits == ["⛔ Buton nevalid sau modificat."]


# --- T3-3: NTEU_TTL_S (7 zile) fixat prin handlerul real -------------------
def test_nteu_ttl_is_seven_days_a_button_six_days_old_still_works(monkeypatch):
    """Fixează valoarea prin EFECT, nu doar prin citirea constantei: un
    buton emis acum 6 zile trebuie să tot funcționeze — `bot.NTEU_TTL_S`
    (7 zile) e mult mai lung decât `callback_ttl_s` implicit (600s) pentru
    că butonul „Nu sunt eu" e gândit să fie apăsat ore sau zile mai târziu."""
    called = {}

    async def _block_and_terminate(db, ip, session_key, *, by, reason):
        called["ip"] = ip
        return {"allowlisted": False, "blocked": True, "terminated": True}

    monkeypatch.setattr(bot.actions, "block_and_terminate", _block_and_terminate)

    six_days_old = int(time.time()) - 6 * 86_400
    data = callback_sign.sign_session_action(KEY, 77, issued_at=six_days_old)
    query = _StubQuery(data)
    db = _NteuDB({"session_key": "s-77", "ip": "203.0.113.7",
                 "username": "op", "closed_at": None}, expected_id=77)
    run(bot.on_callback(_update(query), _context(_cfg(), db=db)))

    assert called.get("ip") == "203.0.113.7"
    assert "Blocat" in query.edits[0]


def test_nteu_ttl_is_seven_days_a_button_just_past_it_is_expired(monkeypatch):
    """Falsificat: cu `NTEU_TTL_S = 600` (fostul implicit al lui `blk:`),
    testul de mai sus ar pica — vezi raportul agentului pentru falsificarea
    ambelor limite ale acestei constante."""
    async def _boom(*_a, **_kw):
        raise AssertionError(
            "block_and_terminate nu trebuia chemat pentru un buton de peste 7 zile")

    monkeypatch.setattr(bot.actions, "block_and_terminate", _boom)

    seven_days_and_five_seconds_old = int(time.time()) - (7 * 86_400 + 5)
    data = callback_sign.sign_session_action(
        KEY, 77, issued_at=seven_days_and_five_seconds_old)
    query = _StubQuery(data)
    run(bot.on_callback(_update(query), _context(_cfg(), db=SimpleNamespace())))

    assert query.edits == ["⛔ Buton expirat."]


# --- T2-4: autorizarea lui on_callback, prin handlerul real ----------------
# `on_callback` verifică ATÂT `_authorized` (chatul, și expeditorul dacă
# `allowed_user_ids` e completat) CÂT ȘI `_can_act` (rolul) înainte de orice
# ramură — netestat direct înainte de asta, spre deosebire de
# `on_flush_callback` (vezi `tests/security/test_telegram_group_sender_check.py`).
# Falsificat: eliminarea oricăreia dintre cele două verificări, sau revenirea
# la `edit_message_text` în loc de `answer(show_alert=True)`, lasă toate trei
# de mai jos verzi din greșeală.
def test_on_callback_refuses_an_unauthorized_chat(monkeypatch):
    """Un chat din afara `allowed_chat_ids` nu are voie să ajungă la nicio
    acțiune — doar la alerta de refuz, fără editare a mesajului (o editare
    ar schimba mesajul pentru toată lumea din chatul ȚINTĂ, nu doar pentru
    expeditorul neautorizat).

    `other_chat` e chiar `owner_chat_id`, dinadins — dacă testul ar lăsa
    `_can_act` să respingă singur cazul ăsta, o mutație care scoate DOAR
    `_authorized` din `on_callback` ar rămâne verde din greșeală. Aici
    `_can_act(other_chat)` ar trece; doar verificarea de CHAT îl oprește."""
    async def _boom(*_a, **_kw):
        raise AssertionError("actions.block nu trebuia chemat pentru un chat neautorizat")

    monkeypatch.setattr(bot.actions, "block", _boom)

    other_chat = CHAT_ID + 1  # NU e în allowed_chat_ids, deși e owner_chat_id
    cfg = SimpleNamespace(telegram=SimpleNamespace(
        allowed_chat_ids=[CHAT_ID], allowed_user_ids=[],
        owner_chat_id=other_chat, operator_chat_ids=[], callback_ttl_s=600))
    data = callback_sign.sign_ip_action("blk", KEY, "203.0.113.7", 3600,
                                        issued_at=int(time.time()))
    query = _StubQuery(data)
    update = SimpleNamespace(callback_query=query,
                             effective_chat=SimpleNamespace(id=other_chat, type="private"),
                             effective_user=SimpleNamespace(id=other_chat))
    run(bot.on_callback(update, _context(cfg, db=SimpleNamespace())))

    assert query.edits == []
    assert query.answers, "trebuia sa raspunda la tap"
    args, kwargs = query.answers[0]
    assert args[0] == "Neautorizat."
    assert kwargs.get("show_alert") is True


def test_on_callback_refuses_a_viewer_chat(monkeypatch):
    """`_can_act` refuză un chat doar-vizualizare: pe `allowed_chat_ids`, deci
    `_authorized`, dar nici owner nici operator, deci fără drept de acțiune."""
    async def _boom(*_a, **_kw):
        raise AssertionError("actions.block nu trebuia chemat pentru un chat viewer")

    monkeypatch.setattr(bot.actions, "block", _boom)

    viewer_chat = CHAT_ID + 2
    cfg = SimpleNamespace(telegram=SimpleNamespace(
        allowed_chat_ids=[CHAT_ID, viewer_chat], allowed_user_ids=[],
        owner_chat_id=CHAT_ID, operator_chat_ids=[], callback_ttl_s=600))
    data = callback_sign.sign_ip_action("blk", KEY, "203.0.113.7", 3600,
                                        issued_at=int(time.time()))
    query = _StubQuery(data)
    update = SimpleNamespace(callback_query=query,
                             effective_chat=SimpleNamespace(id=viewer_chat, type="private"),
                             effective_user=SimpleNamespace(id=viewer_chat))
    run(bot.on_callback(update, _context(cfg, db=SimpleNamespace())))

    assert query.edits == []
    assert query.answers
    args, kwargs = query.answers[0]
    assert args[0] == "Neautorizat."
    assert kwargs.get("show_alert") is True


def test_on_callback_refuses_an_unlisted_sender_in_a_group(monkeypatch):
    """`allowed_user_ids` completat: un membru al grupului care NU e pe listă
    nu trece de `_authorized`, chiar dacă grupul e `owner_chat_id` — exact
    incidentul din 5 septembrie 2026 (docs/TELEGRAM.md §2, §8), aplicat aici
    la butonul de blocare, nu doar la PANIC."""
    async def _boom(*_a, **_kw):
        raise AssertionError("actions.block nu trebuia chemat pentru un expeditor neautorizat")

    monkeypatch.setattr(bot.actions, "block", _boom)

    group_chat = -1009999999999
    member_user = CHAT_ID + 3
    outsider_user = CHAT_ID + 4
    cfg = SimpleNamespace(telegram=SimpleNamespace(
        allowed_chat_ids=[group_chat], allowed_user_ids=[member_user],
        owner_chat_id=group_chat, operator_chat_ids=[], callback_ttl_s=600))
    data = callback_sign.sign_ip_action("blk", KEY, "203.0.113.7", 3600,
                                        issued_at=int(time.time()))
    query = _StubQuery(data)
    update = SimpleNamespace(callback_query=query,
                             effective_chat=SimpleNamespace(id=group_chat, type="group"),
                             effective_user=SimpleNamespace(id=outsider_user))
    run(bot.on_callback(update, _context(cfg, db=SimpleNamespace())))

    assert query.edits == []
    assert query.answers
    args, kwargs = query.answers[0]
    assert args[0] == "Neautorizat."
    assert kwargs.get("show_alert") is True


# --- plasa de siguranță (_guard_callback) --------------------------------
def test_guard_callback_turns_an_unexpected_exception_into_an_alert():
    """Fostul comportament pe orice excepție neprinsă în `on_callback`: tap-ul
    operatorului nu producea NIMIC — nici mesaj, nici jurnal. `_guard_callback`
    e plasa pentru exact asta."""
    async def _raises(update, context):
        raise RuntimeError("boom neasteptat")

    query = _StubQuery("orice")
    update = _update(query)
    context = _context(_cfg(), db=SimpleNamespace())

    run(bot._guard_callback(_raises)(update, context))

    assert query.answers, "trebuia sa raspunda la tap"
    args, kwargs = query.answers[0]
    assert kwargs.get("show_alert") is True


# --- plasa de la urma (app.add_error_handler) ----------------------------
def test_on_telegram_error_logs_and_answers_a_callback(caplog):
    import logging

    from telegram import Update

    # `_on_telegram_error` verifică `isinstance(update, Update)` înainte să
    # răspundă la tap — pe bună dreptate, un `SimpleNamespace` de test ar
    # ascunde exact eroarea pe care isinstance-ul o previne în producție
    # (răspuns la ceva ce nu e un callback real). De asta un `Update` REAL,
    # nu un dublu — biblioteca nu impune tipul câmpurilor la construire, deci
    # dublul de query tot funcționează dedesubt.
    query = _StubQuery("orice")
    update = Update(update_id=1, callback_query=query)
    context = SimpleNamespace(error=RuntimeError("boom"))

    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        run(bot._on_telegram_error(update, context))

    assert any(r.getMessage() == "unhandled telegram update error" for r in caplog.records)
    assert query.answers
    assert query.answers[0][1].get("show_alert") is True


def test_on_telegram_error_does_not_crash_on_an_update_with_no_callback(caplog):
    """Multe update-uri (mesaje simple) n-au `callback_query` — plasa nu are
    voie să presupună că are, altfel un bug diferit de cel original ar apărea
    chiar în cod menit să diagnosticheze bug-uri."""
    import logging

    context = SimpleNamespace(error=ValueError("boom"))
    with caplog.at_level(logging.ERROR, logger="sentinel.telegram.bot"):
        run(bot._on_telegram_error(None, context))  # nu trebuie sa arunce

    assert any(r.getMessage() == "unhandled telegram update error" for r in caplog.records)


def test_error_handler_is_registered_on_the_real_application():
    from sentinel.config import Config

    app = bot.build_application(Config(), _FakeSecrets())
    assert bot._on_telegram_error in app.error_handlers


# --- T2-3: `patch_flow.on_pin_reply` era complet, testat separat, și NEVER --
# WIRED — cu `telegram.require_pin_for_apply: true`, a doua atingere de pe
# „✅ Aplică" trimitea promptul de PIN și rămânea acolo pentru totdeauna:
# niciun `MessageHandler` nu exista în `build_application` ca să ducă un
# răspuns tastat până la `on_pin_reply`. Testul trece prin APLICAȚIA REALĂ
# (`build_application`), găsește handlerul chiar înregistrat acolo — nu
# presupune că linia există — și îi cheamă `.callback` direct, ca să
# dovedească că ajunge la `on_pin_reply`. Falsificat: comentarea liniei de
# înregistrare lasă lista de `MessageHandler` goală.
#
# Runda 3: handlerul e înregistrat prin `_pin_guard`, nu prin `_guard` —
# vezi `tests/unit/test_telegram_pin_journal.py` pentru testele care
# dovedesc DE CE (jurnalizarea PIN-ului) și cele care fixează chiar
# alegerea de înregistrare. Testul ăsta rămâne cel care dovedește doar că
# ajunge la `on_pin_reply`, indiferent prin ce înveliș.
def test_pin_reply_handler_is_registered_and_reaches_on_pin_reply(monkeypatch):
    from telegram.ext import MessageHandler

    from sentinel.config import Config
    from sentinel.telegram import patch_flow

    reached = {}

    async def _fake_on_pin_reply(update, context):
        reached["called"] = True
        return True

    # Legat ÎNAINTE de `build_application`: referința capturată la
    # înregistrare (`_pin_guard(patch_flow.on_pin_reply)`) e cea citită ACUM
    # din `patch_flow`, deci trebuie să fie deja cea falsă când
    # `build_application` rulează.
    monkeypatch.setattr(patch_flow, "on_pin_reply", _fake_on_pin_reply)

    cfg = Config()
    cfg.telegram.allowed_chat_ids = [CHAT_ID]
    app = bot.build_application(cfg, _FakeSecrets())

    handlers = [h for group in app.handlers.values() for h in group
               if isinstance(h, MessageHandler)]
    assert len(handlers) == 1, (
        "handlerul de răspuns la PIN nu e înregistrat (sau s-a înregistrat "
        "mai mult de unul)")

    message = SimpleNamespace(text="123456", caption=None,
                              reply_to_message=None)
    update = SimpleNamespace(effective_chat=SimpleNamespace(id=CHAT_ID),
                             effective_message=message, message=message,
                             effective_user=SimpleNamespace(id=CHAT_ID))
    context = SimpleNamespace(bot_data={"cfg": cfg})

    run(handlers[0].callback(update, context))

    assert reached.get("called") is True, "on_pin_reply nu a fost atins"


class _FakeSecrets:
    def require(self, k):
        return "0:test"

    def has(self, k):
        return True

    def get(self, k, d=None):
        return None
