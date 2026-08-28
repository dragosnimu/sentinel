"""Which Sentinel wrote this message.

Named after the failure it prevents: **27 August 2026, two instances, eight
hours of alerts about the wrong machine.** A Sentinel installed on a test VM
was given production's Telegram token. From 13:10 until 08:32 the next morning
both instances alerted into the same chat. The operator woke to lines like

    🔴 Colector „sshd" a amuțit · de 4h 1m
    🟡 Servicii care rulează cod vechi · de 16h 5m

which were true on the VM and false on production, and not one of them said
which host it came from. Production's own alerts reached nobody at the same
time, because two long-pollers on one token kill each other at `getUpdates`.
An instance name in the first line would have ended it in five seconds.

## What is displayed

The same rule the panel uses — `nameOf` in
`aggregator/app/api/sentinel/check/route.ts`: a label if the operator set one,
`label (id)`, otherwise the bare id. Two readers of the same two values must
not name the same host differently, or "which machine is a3f1?" becomes a
question with two answers. `tests/unit/test_telegram_instance_tag.py` reads
that TypeScript and fails if the convention drifts apart.

One deliberate difference: the id is cut to `SHORT_ID` characters. Thirty-two
hex digits at the top of every alert is a line nobody reads, and a line nobody
reads identifies nothing. Eight is the length a git hash is quoted at, it is a
PREFIX of the real value so it still greps against
`/etc/sentinel/instance_id`, and 16^8 is four billion — two hosts colliding is
not the failure mode worth designing for. The panel keeps showing the full id,
so the short form always maps back to something the operator can look up.

The hostname is deliberately not used. `sentinel/identity.py` argues the case
at length: it changes under a rename or a migration, and it tells whoever reads
a shared panel what the operator's machines are called.

## Where it goes: first line, always

First, because Telegram's push notification shows the beginning of the message
and nothing else — a tag at the foot is a tag the operator has to open the chat
to see, and the whole point is the glance at 03:00. Italic, so it sits under
the bold headline rather than competing with it.

Always, and not behind a configuration key. The day a second instance appears
is precisely the day nobody thinks to switch on the thing that tells two
instances apart; a knob whose default is wrong exactly when it matters is not a
knob. What IS configurable is what the line says: `instance_label` in
`sentinel.yaml` replaces the hex with a name.

## When the identity cannot be read

The message still goes, and it says it does not know. A missing or unreadable
`/etc/sentinel/instance_id` is "I could not look", never "there is nothing to
say" and never a name made up from something else — an invented identity is the
duplicate-identity failure `sentinel/identity.py` exists to prevent, arrived at
through the front door. The diagnosis itself belongs to
`check_instance_identity` in the self-check, which already reports it; this
line only refuses to pretend.

## Read per message, on purpose

`/etc/sentinel/instance_id` is 33 bytes and is read on every send rather than
cached. A cache would mean the first message after the file became unreadable
still carried the old name — which is the same class of lie as reporting a
service healthy from a reading taken an hour ago. Sentinel sends on the order
of a hundred messages a day; the read is not worth the staleness.
"""

from __future__ import annotations

import html as _html
from pathlib import Path
from typing import Any

from sentinel.identity import IdentityError, read_instance_id
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

#: How much of the instance id is shown. See the module docstring for why 8.
SHORT_ID = 8

#: Twin of `MAX_LABEL` in `sentinel/report/beacon.py`, which caps the same
#: value on its way to the aggregator. Capped here too so a runaway string in
#: `sentinel.yaml` cannot eat the message it is supposed to label.
MAX_LABEL = 64

#: What the line says, in the operator's language.
PREFIX = "Instanță: "
UNKNOWN_ID = "id necitibil"
UNKNOWN = "identitate necunoscută"

#: Telegram refuses a message over 4096 characters with a 400, which loses it
#: entirely. `views.MAX_MESSAGE` is 3600 precisely to keep headroom below this,
#: and the instance line is now one of the things that headroom pays for: a
#: clamped message plus the longest this line can be (93 characters, or 349 if
#: every character of the label escapes to five) stays under 4096. The cap
#: below is the backstop for the paths that do NOT clamp — it exists so that
#: adding this line can never be the reason a message is rejected.
TELEGRAM_MAX = 4096

_CUT_HTML = "\n<i>…mesaj scurtat ca să încapă în limita Telegram.</i>"
_CUT_PLAIN = "\n…mesaj scurtat ca să încapă în limita Telegram."
_GONE_HTML = "<i>Mesaj prea lung pentru Telegram; vezi panoul web.</i>"
_GONE_PLAIN = "Mesaj prea lung pentru Telegram; vezi panoul web."


def instance_name(instance_id: str | None, label: Any = "") -> str:
    """`label (id)` when there is a label, otherwise the bare id.

    The last line is `nameOf` from
    `aggregator/app/api/sentinel/check/route.ts`, character for character in
    meaning: a label that is empty or only whitespace is no label, and the id
    stands alone. The panel and the phone must call the same host the same
    thing.

    The branches above it have no counterpart in the aggregator, and cannot:
    there the id is the key of the map being iterated, so it is present by
    construction. Here it comes off a disk that can refuse to be read, and
    saying so is the point.

    `str(label or "")` rather than `label.strip()`, for the reason spelled out
    at `instance_label` in `sentinel/report/beacon.py`: YAML picks the type, so
    `instance_label: 01` arrives as an int and `2026-08-12` as a date. A
    cosmetic field is not allowed to raise AttributeError inside the alerting
    path — that would let a missing pair of quotes silence the channel, which
    is the shape of failure this whole module is named after.
    """
    text = str(label or "").strip()[:MAX_LABEL]
    if not instance_id and not text:
        return UNKNOWN
    ident = instance_id or UNKNOWN_ID
    return f"{text} ({ident})" if text else ident


def current_tag(label: Any = "", *, path: Path | None = None) -> str:
    """This installation's name for a message header. Never raises.

    A failure to read the identity is logged and turned into a name that admits
    it. The caller is on the path that carries alerts; it must not be the place
    where an unreadable file stops the operator from being told anything.
    """
    try:
        instance_id: str | None = read_instance_id(path)
    except IdentityError as exc:
        # Warning, not error: the self-check owns the diagnosis and reports it
        # as a finding. This line exists so the reason is in the journal next
        # to the message that went out saying "necunoscută".
        log.warning("instance identity unreadable; messages will say so",
                    extra={"detail": str(exc)[:300]})
        instance_id = None
    return instance_name(instance_id[:SHORT_ID] if instance_id else None, label)


def tag_for(cfg: Any, *, path: Path | None = None) -> str:
    """The tag for the installation `cfg` describes. Never raises.

    `getattr` with a fallback, which `sentinel/report/beacon.py` argues against
    for the very same field — the asymmetry is the point and it is not a
    relaxation. The three callers of this function
    (`scan/announce.py`, `selfcheck/runner.py`, `services/telegram_service.py`)
    all sit inside a blanket `except` on a best-effort alerting path, so a
    renamed field would not surface as a loud error there: it would swallow the
    whole ANNOUNCEMENT and log one line, trading a security message for a
    cosmetic name. The identifying half of the tag does not come from the
    config at all — it comes off disk. And the loud check still exists: the
    beacon reads `cfg.instance_label` with no fallback and is not wrapped, so a
    rename stops the beacon on the first cycle, which is where it belongs.
    """
    return current_tag(getattr(cfg, "instance_label", ""), path=path)


def header(tag: str, *, html: bool = True) -> str:
    """The one line that goes in front of a message."""
    if html:
        # The label comes from `sentinel.yaml`, which is a file a human edits;
        # a `<` in it would break the markup of every message and Telegram
        # answers 400, so the alert is lost to a character in a cosmetic name.
        return f"<i>{PREFIX}{_html.escape(tag, quote=False)}</i>"
    return f"{PREFIX}{tag}"


def stamp(text: str, tag: str, *, html: bool = True, limit: int = TELEGRAM_MAX) -> str:
    """Put `tag` on the front of `text`, without pushing it over the limit.

    Trimming drops WHOLE LINES from the end and says that it did. Every
    formatter that feeds this closes the markup it opens on the same line
    (`views`, `format_incident`, `format_plan`, `_format_execution`,
    `scan.announce`), so dropping a line cannot leave a `<b>` unclosed — and an
    unclosed tag is worse than a long message, because Telegram rejects it and
    the operator gets nothing at all.

    Idempotent for the same tag: a text that already begins with this header is
    returned untouched, so a path that stamps explicitly and then goes through
    the bot does not say it twice.

    `limit` is assumed to leave room for the header and the "was cut" notice —
    `TELEGRAM_MAX` leaves 3900 characters of it. A limit smaller than those two
    together is not a case this is asked to survive, and the result would be
    the header plus the notice, over the limit.
    """
    head = header(tag, html=html)
    if text == head or text.startswith(head + "\n"):
        return text

    room = limit - len(head) - 1
    if len(text) <= room:
        return f"{head}\n{text}"

    cut = _CUT_HTML if html else _CUT_PLAIN
    budget = room - len(cut)
    kept: list[str] = []
    used = 0
    for line in text.split("\n"):
        need = len(line) + (1 if kept else 0)
        if used + need > budget:
            break
        kept.append(line)
        used += need

    # Logged as well as said in the message: a message that arrives here was
    # built by a formatter with no bound on its length, and that is a defect
    # worth a journal line even though the operator still gets a readable alert.
    log.warning("telegram message trimmed to fit the instance header",
                extra={"chars": len(text), "kept": used})
    if not kept:
        # A single line longer than the whole budget. Nothing in the repository
        # produces one today; it is handled rather than assumed away because
        # the alternative is markup cut in half and a message Telegram refuses.
        return f"{head}\n{_GONE_HTML if html else _GONE_PLAIN}"
    return f"{head}\n" + "\n".join(kept) + cut
