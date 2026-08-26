"""One-shot delivery to Telegram, without going through the bot process.

Two callers need to put text in front of the operator while the bot daemon is
not the thing carrying it:

  * the self-check, when the bot itself is what is down — queuing a message for
    a dead bot is not delivery;
  * `sentinel telegram --send-test`, at the end of an install, when the bot is
    not running yet and the whole point is to prove the channel end to end.

Both used to be their own code, or in the installer's case no code at all. One
implementation means one place where "did it actually arrive" is defined.

## What counts as delivered

The HTTP status is not the answer and neither is the exit code of the request.
Telegram replies `200 {"ok": true, "result": {"message_id": N}}` once it has
accepted the message, and `4xx {"ok": false, "description": "..."}` when the
token is wrong, the chat id is wrong, or the bot has never been started by that
chat. `message_id` is the observable fact: a reply without one is not proof of
anything, and is reported as a failure with whatever Telegram said attached.

A request that could not be made at all — DNS, TLS, timeout, egress blocked —
is also a failure, never a silent skip. "I could not ask" and "nothing is
wrong" are different states and this module never collapses them.

## Plain text by default

`parse_mode` defaults to None, i.e. Telegram treats the text literally. The
installer's test message interpolates `${DOMAIN:-<fara domeniu>}`, and under
HTML that `<fara domeniu>` is an unclosed tag: Telegram answers 400 "can't
parse entities" and the end-to-end proof fails for a reason that has nothing to
do with the channel. Callers that send markup ask for it explicitly.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

# Per request, not for the whole batch. The caller decides what to do about the
# total; what matters here is that no single call can block forever, because the
# thing this module is used by is an installer step and a self-check, and both
# have to come back with a verdict.
DEFAULT_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class SendOutcome:
    """What Telegram said about one chat. `ok` only when a message_id came back."""

    chat_id: int
    ok: bool
    message_id: int | None = None
    error: str | None = None

    def describe(self) -> str:
        # ASCII only, deliberately. This line is printed by `sentinel telegram
        # --send-test`, which the installer runs over ssh with whatever locale
        # the session happens to have. Under LC_ALL=C a single em dash is a
        # UnicodeEncodeError, and the verdict the operator needs becomes a
        # traceback. This repository has already lost a day to one diacritic.
        if self.ok:
            return f"chat {self.chat_id}: delivered (message_id={self.message_id})"
        return f"chat {self.chat_id}: FAILED: {self.error}"


def _read_reply(status: int, payload: object) -> tuple[bool, int | None, str | None]:
    """Turn one Telegram reply into a verdict.

    Split out from the request so it can be read on its own: this is the part
    that decides whether the operator's phone will ring, and it must not treat
    "200 with a body I did not understand" as success.
    """
    if not isinstance(payload, dict):
        return False, None, f"HTTP {status}, body is not a JSON object"
    if not payload.get("ok"):
        detail = payload.get("description") or "no description"
        return False, None, f"HTTP {status}: {detail}"
    result = payload.get("result")
    message_id = result.get("message_id") if isinstance(result, dict) else None
    if not isinstance(message_id, int):
        return False, None, f"HTTP {status}: ok=true but no message_id in the reply"
    return True, message_id, None


async def send_to_chats(
    token: str,
    chat_ids: Iterable[int],
    text: str,
    *,
    parse_mode: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> list[SendOutcome]:
    """Send `text` to every chat, one request each, and report each one.

    Never raises for a failed send: the caller decides what a partial failure
    means. It returns one outcome per chat id, in order, so a caller can name
    the chat that did not get it rather than reporting a single boolean.
    """
    import httpx

    ids: Sequence[int] = list(chat_ids)
    outcomes: list[SendOutcome] = []
    if not ids:
        return outcomes

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        for chat_id in ids:
            body: dict[str, object] = {"chat_id": chat_id, "text": text}
            if parse_mode:
                body["parse_mode"] = parse_mode
            try:
                response = await client.post(url, json=body)
            except Exception as exc:  # noqa: BLE001 - the reason is the diagnostic
                # The exception type is part of the message on purpose:
                # ConnectTimeout, ReadTimeout and ConnectError send an operator
                # to three different places, and `str(exc)` alone is often empty.
                outcomes.append(SendOutcome(
                    chat_id, False,
                    error=f"{type(exc).__name__}: {exc or 'no detail'}"))
                continue
            try:
                payload = response.json()
            except Exception:  # noqa: BLE001 - a non-JSON reply is not delivery
                payload = None
            ok, message_id, error = _read_reply(response.status_code, payload)
            outcomes.append(SendOutcome(chat_id, ok, message_id, error))
    return outcomes
