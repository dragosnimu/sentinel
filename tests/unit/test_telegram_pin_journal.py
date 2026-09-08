"""Round 3: a typed PIN must never reach journald, right or wrong.

T3-1: `on_pin_reply` used to be wired through `_guard`, which logs the
accepted message's own text at INFO (`"command": text[:200]`) and calls
`chats_repo.record_command`. For every other handler that is "what command
ran" — exactly what the operator wants recorded. For a PIN reply it means
the operator's own PIN, correct OR wrong, sitting in journald in clear text,
readable by the `sentinel` uid on both hosts (`adm`, `systemd-journal`).
`redact()` (`sentinel/util/shellsafe.py`) does not catch it: it matches
`password=`/token/URL-credential/PEM shapes, not a bare six digits that
happens to be typed while a PIN wait is pending.

`bot.py::_pin_guard` is the fix: registered in place of `_guard` for this one
handler, it never logs message text and never calls `record_command`. Every
test here drives the update through the REAL handler `build_application`
registers — reading `bot._pin_guard` in isolation would prove the wrapper
does the right thing, not that `build_application` actually uses it, and a
one-line registration slip (`_guard(patch_flow.on_pin_reply)` again) is
exactly the regression T3-1 exists to catch.

A second failure mode lives in the same handler: the PTB filter
(`filters.TEXT & ~filters.COMMAND & filters.REPLY`) cannot see
`patch_flow`'s pending-PIN state at match time, so it also matches an
ordinary human reply to some OTHER bot message — someone answering an
incident alert while, by coincidence, a PIN happens to be pending in the
same chat. That must produce no log record at all, not even a redacted one:
counting an ordinary reply as a "pin attempt" event is its own kind of
noise, and it is not what actually happened.
"""
from __future__ import annotations

import asyncio
import logging
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.telegram import bot, patch_flow  # noqa: E402

PROMPT_MESSAGE_ID = 555
BOT_LOGGER = "sentinel.telegram.bot"


def run(c):
    return asyncio.run(c)


# --- fakes, tailored to what _pin_guard and on_pin_reply actually touch ----
class _FakeMessage:
    def __init__(self, text: str = "", *, reply_to_message_id: int | None = None):
        self.text = text
        self.caption = None
        self.replies: list["_FakeMessage"] = []
        self.reply_to_message = (
            SimpleNamespace(message_id=reply_to_message_id)
            if reply_to_message_id is not None else None)

    async def reply_text(self, text, **kw):
        msg = _FakeMessage()
        msg.sent_as_reply_text = text  # type: ignore[attr-defined]
        self.replies.append(msg)
        return msg

    async def edit_text(self, text, **kw):
        self.sent_as_reply_text = text  # type: ignore[attr-defined]


class _FakeChat:
    def __init__(self, chat_id: int, chat_type: str = "private"):
        self.id = chat_id
        self.type = chat_type


class _FakeUpdate:
    """Duck-types exactly the two properties `_pin_guard` and `on_pin_reply`
    read: `effective_chat` and (`effective_message` == `message`, as PTB
    itself aliases them for a plain message update)."""

    def __init__(self, *, chat_id: int, text: str | None = None,
                 reply_to_message_id: int | None = None, chat_type: str = "private"):
        self.effective_chat = _FakeChat(chat_id, chat_type)
        msg = (_FakeMessage(text or "", reply_to_message_id=reply_to_message_id)
               if text is not None else None)
        self.message = msg
        self.effective_message = msg
        self.effective_user = SimpleNamespace(id=chat_id)


class _FakeSecrets:
    """`build_application` needs a `Secrets`-shaped object to construct the
    bot itself, not to answer PIN questions — `on_pin_reply` reads the PIN
    through `sentinel.config.get_secrets()`, monkeypatched per test below."""

    def require(self, key):
        return "0:test"

    def has(self, key):
        return True

    def get(self, key, default=None):
        return default


class _FakePinSecrets:
    def __init__(self, pin: str | None):
        self._pin = pin

    def get(self, key: str, default=None):
        return self._pin if key == "TELEGRAM_APPLY_PIN" else default


def _cfg(allowed_chat_ids):
    from sentinel.config import Config
    cfg = Config()
    cfg.telegram.allowed_chat_ids = list(allowed_chat_ids)
    return cfg


def _pin_handler(cfg):
    """The handler `build_application` actually registers for a PIN reply —
    never `patch_flow.on_pin_reply` called directly, and never `bot._pin_guard`
    applied by hand: both would prove the wrapper works, not that the real
    registration line uses it."""
    from telegram.ext import MessageHandler

    app = bot.build_application(cfg, _FakeSecrets())
    handlers = [h for group in app.handlers.values() for h in group
               if isinstance(h, MessageHandler)]
    assert len(handlers) == 1, "handlerul de răspuns la PIN nu e înregistrat"
    return handlers[0].callback


def _mentions(caplog, needle: str) -> bool:
    """True if `needle` appears anywhere in any captured record — message
    text OR any extra field — not just the ones this test happens to check."""
    for record in caplog.records:
        if needle in record.getMessage():
            return True
        for value in vars(record).values():
            if isinstance(value, str) and needle in value:
                return True
    return False


@pytest.fixture(autouse=True)
def _clean_pending():
    """`_pending_pins` is module-level, in-process state — the same reason
    `tests/security/test_patch_pin.py` clears it around every test."""
    patch_flow._pending_pins.clear()
    yield
    patch_flow._pending_pins.clear()


def _never_record_command(monkeypatch):
    async def _boom(*a, **kw):
        raise AssertionError(
            "chats_repo.record_command must never be called for a PIN reply "
            "— it is not a command")
    monkeypatch.setattr(bot.chats_repo, "record_command", _boom)


# --- the PIN itself must never appear in a log record -----------------------
def test_a_correct_pin_is_never_journaled_and_is_not_recorded_as_a_command(
        monkeypatch, caplog):
    """Falsified: registering this handler through `_guard` again (the
    round-1 bug) puts `"246810"` straight into the `command` field of the
    INFO line `_guard` emits on every accepted message — confirmed by hand,
    restored immediately after (see agent report)."""
    _never_record_command(monkeypatch)
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakePinSecrets("246810"))

    async def _approve(db, plan_id, *, by, expected_hash):
        return True

    async def _revoke(*a, **kw):
        pass

    async def _run_plan(db, cfg, plan_id, *, mode, triggered_by):
        return SimpleNamespace(status="succeeded", execution_id=1, error=None, steps=[])

    monkeypatch.setattr(patch_flow.patches, "approve_plan", _approve)
    monkeypatch.setattr(patch_flow.approvals, "revoke_for_plan", _revoke)
    monkeypatch.setattr("sentinel.patch.runner.run_plan", _run_plan)

    chat_id = 900001
    patch_flow._pending_pins[chat_id] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by=f"telegram:{chat_id}",
        expires_at=time.monotonic() + 300, prompt_message_id=PROMPT_MESSAGE_ID)

    cfg = _cfg([chat_id])
    handler = _pin_handler(cfg)
    update = _FakeUpdate(chat_id=chat_id, text="246810",
                         reply_to_message_id=PROMPT_MESSAGE_ID)
    context = SimpleNamespace(bot_data={"db": object(), "cfg": cfg})

    with caplog.at_level(logging.DEBUG):
        run(handler(update, context))

    assert not _mentions(caplog, "246810"), "PIN-ul corect a ajuns într-o linie de jurnal"
    assert chat_id not in patch_flow._pending_pins  # aplicat, deci consumat

    pin_records = [r for r in caplog.records if r.getMessage() == "pin attempt"]
    assert len(pin_records) == 1, "trebuia exact o linie 'pin attempt'"
    assert pin_records[0].outcome == "ok"
    assert pin_records[0].chat_id == chat_id
    assert not hasattr(pin_records[0], "command"), (
        "linia nu are voie să poarte un câmp 'command' — asta ar fi textul brut")


def test_a_wrong_pin_is_never_journaled_either(monkeypatch, caplog):
    """Un PIN greșit e la fel de secret ca unul corect — cine îl scrie
    tastează adesea o variantă a celui adevărat cu o cifră greșită."""
    _never_record_command(monkeypatch)
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakePinSecrets("246810"))

    chat_id = 900002
    patch_flow._pending_pins[chat_id] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by=f"telegram:{chat_id}",
        expires_at=time.monotonic() + 300, prompt_message_id=PROMPT_MESSAGE_ID)

    cfg = _cfg([chat_id])
    handler = _pin_handler(cfg)
    update = _FakeUpdate(chat_id=chat_id, text="000000",
                         reply_to_message_id=PROMPT_MESSAGE_ID)
    context = SimpleNamespace(bot_data={"db": object(), "cfg": cfg})

    with caplog.at_level(logging.DEBUG):
        run(handler(update, context))

    assert not _mentions(caplog, "000000"), "PIN-ul tastat greșit a ajuns într-o linie de jurnal"
    assert not _mentions(caplog, "246810"), "PIN-ul configurat a ajuns într-o linie de jurnal"

    pin_records = [r for r in caplog.records if r.getMessage() == "pin attempt"]
    assert len(pin_records) == 1
    assert pin_records[0].outcome == "wrong"
    assert pin_records[0].chat_id == chat_id
    assert patch_flow._pending_pins[chat_id].attempts == 1


def test_an_expired_pin_wait_is_logged_only_as_expired(monkeypatch, caplog):
    _never_record_command(monkeypatch)
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakePinSecrets("246810"))

    chat_id = 900003
    patch_flow._pending_pins[chat_id] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by=f"telegram:{chat_id}",
        expires_at=time.monotonic() - 1, prompt_message_id=PROMPT_MESSAGE_ID)

    cfg = _cfg([chat_id])
    handler = _pin_handler(cfg)
    update = _FakeUpdate(chat_id=chat_id, text="246810",
                         reply_to_message_id=PROMPT_MESSAGE_ID)
    context = SimpleNamespace(bot_data={"db": object(), "cfg": cfg})

    with caplog.at_level(logging.DEBUG):
        run(handler(update, context))

    assert not _mentions(caplog, "246810")
    pin_records = [r for r in caplog.records if r.getMessage() == "pin attempt"]
    assert len(pin_records) == 1
    assert pin_records[0].outcome == "expired"


# --- an ordinary human reply must not be logged at all ----------------------
def test_a_human_reply_to_a_different_bot_message_produces_no_log_record_at_all(
        monkeypatch, caplog):
    """The exact case `on_pin_reply` itself was built to refuse (S2 round 2):
    a reply to some OTHER message while a PIN happens to be pending in the
    same chat. It must not be logged as a PIN attempt of any kind, and it
    must not be counted as a command — both would be recording something
    that never happened.

    Falsified: dropping the `if not handled ...: return` guard in
    `_pin_guard` (logging unconditionally after calling the handler) makes
    this red — confirmed by hand, restored (see agent report)."""
    _never_record_command(monkeypatch)
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakePinSecrets("246810"))

    chat_id = 900004
    patch_flow._pending_pins[chat_id] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by=f"telegram:{chat_id}",
        expires_at=time.monotonic() + 300, prompt_message_id=PROMPT_MESSAGE_ID)

    cfg = _cfg([chat_id])
    handler = _pin_handler(cfg)
    # A reply to a DIFFERENT message — an ordinary reply in the same chat,
    # not the PIN prompt.
    update = _FakeUpdate(chat_id=chat_id, text="mersi, am văzut alerta",
                         reply_to_message_id=PROMPT_MESSAGE_ID + 1)
    context = SimpleNamespace(bot_data={"db": object(), "cfg": cfg})

    with caplog.at_level(logging.DEBUG):
        run(handler(update, context))

    assert not _mentions(caplog, "mersi, am văzut alerta")
    assert not any(r.getMessage() == "pin attempt" for r in caplog.records), (
        "un răspuns obișnuit a fost jurnalizat ca o încercare de PIN")
    # Şi efectul lui `on_pin_reply`, nu doar jurnalul: n-a ars nicio încercare.
    assert patch_flow._pending_pins[chat_id].attempts == 0


def test_a_human_reply_with_no_pin_pending_at_all_produces_no_log_record(caplog):
    """Cazul de bază: niciun PIN în așteptare pentru chatul ăsta — orice
    răspuns text e conversație obișnuită, nu o încercare de nimic."""
    chat_id = 900005
    cfg = _cfg([chat_id])
    handler = _pin_handler(cfg)
    update = _FakeUpdate(chat_id=chat_id, text="salut", reply_to_message_id=12345)
    context = SimpleNamespace(bot_data={"db": object(), "cfg": cfg})

    with caplog.at_level(logging.DEBUG):
        run(handler(update, context))

    assert not any(r.getMessage() == "pin attempt" for r in caplog.records)


# --- unauthorised chat: refused silently, logged without text ---------------
def test_an_unauthorized_chat_is_refused_silently_and_never_reaches_on_pin_reply(
        monkeypatch, caplog):
    """`_authorized` gates BEFORE `on_pin_reply` runs at all — a PIN typed in
    a chat that fell out of `allowed_chat_ids` must not even be compared."""
    _never_record_command(monkeypatch)

    async def _boom(*a, **kw):
        raise AssertionError("on_pin_reply must not run for an unauthorized chat")

    monkeypatch.setattr(patch_flow, "on_pin_reply", _boom)

    chat_id = 900006
    cfg = _cfg([chat_id + 1])  # chat_id NOT in allowed_chat_ids
    handler = _pin_handler(cfg)
    update = _FakeUpdate(chat_id=chat_id, text="246810", reply_to_message_id=PROMPT_MESSAGE_ID)
    context = SimpleNamespace(bot_data={"db": object(), "cfg": cfg})

    with caplog.at_level(logging.DEBUG):
        run(handler(update, context))

    assert update.message.replies == [], "un chat neautorizat nu trebuie să primească niciun răspuns"
    assert not _mentions(caplog, "246810")
    pin_records = [r for r in caplog.records if r.getMessage() == "pin attempt"]
    assert len(pin_records) == 1
    assert pin_records[0].outcome == "ignored"
    assert pin_records[0].chat_id == chat_id


# --- T3-2: pin the registration itself, not just the wrapper's behaviour ----
def test_the_pin_handler_is_registered_through_pin_guard_not_guard():
    """Falsified: reverting the registration line to
    `_guard(patch_flow.on_pin_reply)` makes this red — confirmed by hand,
    restored (see agent report)."""
    cfg = _cfg([1])
    handler = _pin_handler(cfg)
    # `_guard` and `_pin_guard` both close over a variable named `handler`
    # (see `tests/security/test_telegram_callback_routes.py::_unwrapped_target`
    # for the same technique) — but their OUTER function differs, and that is
    # exactly what `__qualname__` records.
    assert handler.__qualname__.startswith("_pin_guard."), (
        f"handlerul de PIN nu mai e înregistrat prin _pin_guard: {handler.__qualname__!r}")
    assert not handler.__qualname__.startswith("_guard."), (
        "handlerul de PIN e din nou înregistrat prin _guard — exact bug-ul "
        "de rundă 1: PIN-ul ar ajunge în jurnal ca 'command'")


def test_the_pin_handler_filter_still_requires_a_reply(monkeypatch):
    """T3-2: dacă `filters.REPLY` dispare din înregistrare, un mesaj text
    obișnuit (care NU e răspuns la nimic) ar ajunge la handler — verificat
    prin filtrul REAL al PTB, pe un update REAL de tip mesaj, nu pe o
    presupunere despre ce conține obiectul `filters`."""
    from telegram import Chat, Message, Update, User

    cfg = _cfg([1])
    app = bot.build_application(cfg, _FakeSecrets())
    from telegram.ext import MessageHandler
    handlers = [h for group in app.handlers.values() for h in group
               if isinstance(h, MessageHandler)]
    assert len(handlers) == 1
    registered_filter = handlers[0].filters

    user = User(id=1, first_name="t", is_bot=False)
    chat = Chat(id=1, type="private")
    non_reply = Message(message_id=1, date=None, chat=chat, from_user=user,
                        text="salut", reply_to_message=None)
    assert registered_filter.check_update(
        Update(update_id=1, message=non_reply)) in (False, None, {}), (
        "un mesaj care NU e răspuns la nimic a trecut de filtru — "
        "filters.REPLY lipsește din înregistrare")
