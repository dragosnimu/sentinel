"""S2: `telegram.require_pin_for_apply` must actually gate an apply.

Before this fix `patch_flow.on_stage2` never read the setting at all — the
second tap approved and ran the plan exactly the same whether the option was
on or off. A phone lost or stolen mid-approval bought an attacker nothing
extra from turning it on, which is the opposite of "defence in depth".

Every test drives the real handlers (`on_stage2`, `on_pin_reply`) with a
constructed fake `Update`/`context`, never a source-text grep — the whole
point is to prove the PIN gate has an observable EFFECT (approve_plan and
run_plan are or are not called), not that the right words appear in the file.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from sentinel.telegram import patch_flow


def run(c):
    return asyncio.run(c)


# --- fakes -------------------------------------------------------------
class _FakeMessage:
    def __init__(self, text: str = "", *, message_id: int | None = None,
                 reply_to_message_id: int | None = None):
        self.text = text
        self.message_id = message_id
        self.edits: list[str] = []
        self.replies: list["_FakeMessage"] = []
        # S2 (round 2): `on_pin_reply` requires the reply to point AT the
        # PIN prompt's own message — a bare SimpleNamespace with just
        # `message_id` is enough, since that field is all the handler reads.
        self.reply_to_message = (
            SimpleNamespace(message_id=reply_to_message_id)
            if reply_to_message_id is not None else None)

    async def edit_text(self, text: str, **kw: Any) -> None:
        self.edits.append(text)

    async def reply_text(self, text: str, **kw: Any) -> "_FakeMessage":
        msg = _FakeMessage()
        self.replies.append(msg)
        msg.sent_as_reply_text = text  # type: ignore[attr-defined]
        return msg


# The fixed id every test's PIN prompt "sends" as — production reads
# whatever `edit_message_text` actually returns, but a fixed constant here
# is enough for a fake that only exists to carry the id back and forth.
PROMPT_MESSAGE_ID = 555


class _FakeQuery:
    def __init__(self):
        self.edits: list[str] = []

    async def edit_message_text(self, text: str, **kw: Any) -> _FakeMessage:
        self.edits.append(text)
        return _FakeMessage(message_id=PROMPT_MESSAGE_ID)


class _FakeChat:
    def __init__(self, chat_id: int):
        self.id = chat_id


class _FakeUpdate:
    """Duck-types just what patch_flow's handlers touch."""

    def __init__(self, *, chat_id: int, text: str | None = None,
                 with_callback_query: bool = False,
                 reply_to_message_id: int | None = PROMPT_MESSAGE_ID):
        self.effective_chat = _FakeChat(chat_id)
        self.message = (
            _FakeMessage(text or "", reply_to_message_id=reply_to_message_id)
            if text is not None else None)
        self.callback_query = _FakeQuery() if with_callback_query else None


class _FakeSecrets:
    def __init__(self, pin: str | None):
        self._pin = pin

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._pin if key == "TELEGRAM_APPLY_PIN" else default


def _cfg(require_pin: bool) -> Any:
    return SimpleNamespace(telegram=SimpleNamespace(require_pin_for_apply=require_pin))


def _second_tap_context(cfg: Any) -> Any:
    return SimpleNamespace(bot_data={"db": object(), "cfg": cfg})


@pytest.fixture(autouse=True)
def _clean_pending():
    """`_pending_pins` is module-level, in-process state — clear it around
    every test so one test's PIN wait cannot leak into the next."""
    patch_flow._pending_pins.clear()
    yield
    patch_flow._pending_pins.clear()


@pytest.fixture
def _no_approve_or_run(monkeypatch):
    """Fails the test loudly if approve_plan or run_plan is ever reached —
    used by every test asserting the gate BLOCKS."""
    async def _boom_approve(*a, **kw):
        raise AssertionError("approve_plan must not run before the PIN succeeds")

    async def _boom_run(*a, **kw):
        raise AssertionError("run_plan must not run before the PIN succeeds")

    monkeypatch.setattr(patch_flow.patches, "approve_plan", _boom_approve)
    monkeypatch.setattr("sentinel.patch.runner.run_plan", _boom_run)


class _Stage2Second:
    """Stands in for what `approvals.consume` returns on the second tap."""
    stage = 2
    plan_id = 42
    plan_hash = "abc123"


@pytest.fixture
def _stage2_scaffolding(monkeypatch):
    """Everything on_stage2 needs before it reaches the PIN gate: a valid
    stage-2 token and a plan not caught by the window halt."""
    async def _consume(*a, **kw):
        return _Stage2Second()

    async def _get_plan(*a, **kw):
        return SimpleNamespace(proposed_by_window=False)

    monkeypatch.setattr(patch_flow.approvals, "consume", _consume)
    monkeypatch.setattr(patch_flow.patches, "get_plan", _get_plan)


# --- the gate itself ------------------------------------------------------
def test_pin_disabled_applies_exactly_as_before(monkeypatch, _stage2_scaffolding):
    """The control: with the option off, nothing about this fix changes the
    existing (already-tested) apply path."""
    called = {}

    async def _approve(db, plan_id, *, by, expected_hash):
        called["approve"] = (plan_id, expected_hash)
        return True

    async def _revoke(*a, **kw):
        called["revoked"] = True

    async def _run_plan(db, cfg, plan_id, *, mode, triggered_by):
        return SimpleNamespace(status="succeeded", execution_id=1, error=None, steps=[])

    monkeypatch.setattr(patch_flow.patches, "approve_plan", _approve)
    monkeypatch.setattr(patch_flow.approvals, "revoke_for_plan", _revoke)
    monkeypatch.setattr("sentinel.patch.runner.run_plan", _run_plan)

    update = _FakeUpdate(chat_id=1, with_callback_query=True)
    run(patch_flow.on_stage2(update, _second_tap_context(_cfg(False)), "tok"))

    assert called.get("approve") == (42, "abc123")
    assert called.get("revoked") is True
    assert 1 not in patch_flow._pending_pins


def test_pin_required_but_not_configured_refuses_instead_of_applying(
        monkeypatch, _stage2_scaffolding, _no_approve_or_run):
    """`require_pin_for_apply: true` with an empty TELEGRAM_APPLY_PIN must be
    a refusal, never "any reply matches" and never a silent bypass."""
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets(None))

    update = _FakeUpdate(chat_id=2, with_callback_query=True)
    run(patch_flow.on_stage2(update, _second_tap_context(_cfg(True)), "tok"))

    assert any("TELEGRAM_APPLY_PIN" in m for m in update.callback_query.edits)
    assert 2 not in patch_flow._pending_pins


def test_pin_required_stages_a_wait_and_does_not_apply_yet(
        monkeypatch, _stage2_scaffolding, _no_approve_or_run):
    """This is the exact bug: before the fix, this call applied the plan
    regardless of the option. Now it must only ever prompt for the PIN."""
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("13579"))

    update = _FakeUpdate(chat_id=3, with_callback_query=True)
    run(patch_flow.on_stage2(update, _second_tap_context(_cfg(True)), "tok"))

    assert 3 in patch_flow._pending_pins
    pending = patch_flow._pending_pins[3]
    assert (pending.plan_id, pending.plan_hash) == (42, "abc123")
    assert pending.prompt_message_id == PROMPT_MESSAGE_ID, (
        "the prompt's own message_id was not recorded — on_pin_reply cannot "
        "require the reply to point at it")
    assert any("PIN" in m for m in update.callback_query.edits)


def test_correct_pin_reply_applies_the_plan(monkeypatch):
    called = {}

    async def _approve(db, plan_id, *, by, expected_hash):
        called["approve"] = (plan_id, expected_hash, by)
        return True

    async def _revoke(*a, **kw):
        called["revoked"] = True

    async def _run_plan(db, cfg, plan_id, *, mode, triggered_by):
        called["ran"] = (plan_id, mode)
        return SimpleNamespace(status="succeeded", execution_id=9, error=None, steps=[])

    monkeypatch.setattr(patch_flow.patches, "approve_plan", _approve)
    monkeypatch.setattr(patch_flow.approvals, "revoke_for_plan", _revoke)
    monkeypatch.setattr("sentinel.patch.runner.run_plan", _run_plan)
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("13579"))

    import time
    patch_flow._pending_pins[4] = patch_flow._PendingPin(
        plan_id=99, plan_hash="deadbeef", by="telegram:4",
        expires_at=time.monotonic() + 300, prompt_message_id=PROMPT_MESSAGE_ID)

    update = _FakeUpdate(chat_id=4, text="13579")
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    handled = run(patch_flow.on_pin_reply(update, context))

    assert handled is True
    assert called["approve"] == (99, "deadbeef", "telegram:4")
    assert called["ran"] == (99, "apply")
    assert 4 not in patch_flow._pending_pins


def test_wrong_pin_does_not_apply_and_counts_the_attempt(monkeypatch, _no_approve_or_run):
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("13579"))
    import time
    patch_flow._pending_pins[5] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by="telegram:5", expires_at=time.monotonic() + 300,
        prompt_message_id=PROMPT_MESSAGE_ID)

    update = _FakeUpdate(chat_id=5, text="00000")
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    handled = run(patch_flow.on_pin_reply(update, context))

    assert handled is True
    assert 5 in patch_flow._pending_pins       # still pending, one attempt used
    assert patch_flow._pending_pins[5].attempts == 1


def test_pin_attempts_are_capped_per_chat(monkeypatch, _no_approve_or_run):
    """A stolen phone must not get unlimited guesses at a short static PIN."""
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("13579"))
    import time
    patch_flow._pending_pins[6] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by="telegram:6", expires_at=time.monotonic() + 300,
        prompt_message_id=PROMPT_MESSAGE_ID)

    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    for _ in range(patch_flow.PIN_MAX_ATTEMPTS):
        run(patch_flow.on_pin_reply(_FakeUpdate(chat_id=6, text="wrong"), context))

    assert 6 not in patch_flow._pending_pins   # locked out
    # One more reply now has nothing pending to consume.
    handled = run(patch_flow.on_pin_reply(_FakeUpdate(chat_id=6, text="13579"), context))
    assert handled is False


def test_expired_pending_pin_is_rejected(monkeypatch, _no_approve_or_run):
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("13579"))
    import time
    patch_flow._pending_pins[7] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by="telegram:7", expires_at=time.monotonic() - 1,
        prompt_message_id=PROMPT_MESSAGE_ID)

    update = _FakeUpdate(chat_id=7, text="13579")
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    handled = run(patch_flow.on_pin_reply(update, context))

    assert handled is True
    assert 7 not in patch_flow._pending_pins
    assert any("expirat" in r.sent_as_reply_text for r in update.message.replies)


def test_no_pending_pin_is_not_consumed():
    """A chat with nothing pending must not have its ordinary messages
    swallowed by this handler."""
    update = _FakeUpdate(chat_id=8, text="hello")
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    assert run(patch_flow.on_pin_reply(update, context)) is False


# --- S2 round 2: the reply must point at the PIN prompt itself -------------
def test_a_reply_to_a_different_message_is_not_consumed_as_a_pin_attempt(
        monkeypatch, _no_approve_or_run):
    """The exact failure this prevents: without pinning to the prompt's own
    message_id, ANY text reply sent to this chat while a PIN happens to be
    pending — a reply to something else entirely — would be swallowed as a
    WRONG PIN attempt. Three of those by accident burns every
    `PIN_MAX_ATTEMPTS` and locks the operator out of the approval they
    actually meant to make."""
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("13579"))
    import time
    patch_flow._pending_pins[9] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by="telegram:9", expires_at=time.monotonic() + 300,
        prompt_message_id=PROMPT_MESSAGE_ID)

    # A reply to some OTHER message (id differs from the PIN prompt's).
    update = _FakeUpdate(chat_id=9, text="unrelated reply",
                         reply_to_message_id=PROMPT_MESSAGE_ID + 1)
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    handled = run(patch_flow.on_pin_reply(update, context))

    assert handled is False, "a reply to a different message was treated as a PIN attempt"
    assert 9 in patch_flow._pending_pins
    assert patch_flow._pending_pins[9].attempts == 0, (
        "an unrelated reply must not burn a PIN attempt")


def test_a_message_that_is_not_a_reply_at_all_is_not_consumed(monkeypatch, _no_approve_or_run):
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("13579"))
    import time
    patch_flow._pending_pins[10] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by="telegram:10", expires_at=time.monotonic() + 300,
        prompt_message_id=PROMPT_MESSAGE_ID)

    update = _FakeUpdate(chat_id=10, text="13579", reply_to_message_id=None)
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    handled = run(patch_flow.on_pin_reply(update, context))

    assert handled is False
    assert patch_flow._pending_pins[10].attempts == 0


# --- S2 round 2: non-ASCII must not crash the comparison --------------------
def test_a_non_ascii_typed_pin_is_rejected_not_a_crash(monkeypatch, _no_approve_or_run):
    """`hmac.compare_digest` raises `TypeError` on a `str` outside ASCII —
    before encoding both sides to bytes, an operator fat-fingering a
    diacritic while typing the PIN would crash this handler instead of
    just being told the PIN was wrong."""
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("13579"))
    import time
    patch_flow._pending_pins[11] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by="telegram:11", expires_at=time.monotonic() + 300,
        prompt_message_id=PROMPT_MESSAGE_ID)

    update = _FakeUpdate(chat_id=11, text="ă1234")
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    handled = run(patch_flow.on_pin_reply(update, context))  # must not raise

    assert handled is True
    assert patch_flow._pending_pins[11].attempts == 1


def test_pin_reply_refuses_if_the_configured_pin_disappeared_since_the_prompt(
        monkeypatch, _no_approve_or_run):
    """`expected is None` must short-circuit the comparison, not skip it —
    if `TELEGRAM_APPLY_PIN` is unset (or was removed from secrets.env)
    between the prompt and the reply, this must refuse exactly like a wrong
    PIN, never like "no PIN required, go ahead". Falsified: inverting the
    guard to `expected is not None` makes this pass silently with
    `approve_plan` reached — confirmed by hand during review, restored
    immediately after.
    """
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets(None))
    import time
    patch_flow._pending_pins[13] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by="telegram:13", expires_at=time.monotonic() + 300,
        prompt_message_id=PROMPT_MESSAGE_ID)

    update = _FakeUpdate(chat_id=13, text="anything")
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    handled = run(patch_flow.on_pin_reply(update, context))

    assert handled is True
    assert 13 in patch_flow._pending_pins
    assert patch_flow._pending_pins[13].attempts == 1


def test_a_non_ascii_configured_pin_can_still_be_matched(monkeypatch):
    """The other direction: `TELEGRAM_APPLY_PIN` itself containing a
    diacritic ("parolă") must be a real, matchable secret, not a value that
    can never compare equal to anything once encoding is involved."""
    called = {}

    async def _approve(db, plan_id, *, by, expected_hash):
        called["approve"] = True
        return True

    async def _revoke(*a, **kw):
        pass

    async def _run_plan(db, cfg, plan_id, *, mode, triggered_by):
        return SimpleNamespace(status="succeeded", execution_id=1, error=None, steps=[])

    monkeypatch.setattr(patch_flow.patches, "approve_plan", _approve)
    monkeypatch.setattr(patch_flow.approvals, "revoke_for_plan", _revoke)
    monkeypatch.setattr("sentinel.patch.runner.run_plan", _run_plan)
    monkeypatch.setattr("sentinel.config.get_secrets", lambda: _FakeSecrets("parolă"))

    import time
    patch_flow._pending_pins[12] = patch_flow._PendingPin(
        plan_id=1, plan_hash="x", by="telegram:12", expires_at=time.monotonic() + 300,
        prompt_message_id=PROMPT_MESSAGE_ID)

    update = _FakeUpdate(chat_id=12, text="parolă")
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg(True)})
    handled = run(patch_flow.on_pin_reply(update, context))

    assert handled is True
    assert called.get("approve") is True
    assert 12 not in patch_flow._pending_pins


def test_pin_compared_constant_time():
    """`hmac.compare_digest`, not `==` — a PIN this short is brute-forceable
    over enough timing samples otherwise."""
    import inspect
    assert "hmac.compare_digest" in inspect.getsource(patch_flow.on_pin_reply)
