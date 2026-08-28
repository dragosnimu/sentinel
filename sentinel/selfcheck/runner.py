"""Run the checks, decide what is worth saying, and make sure it gets said.

## When it speaks

On **change**, not on state. A check that has been failing for six hours is not
six hundred messages; it is one message when it broke, one when it recovered,
and a reminder every few hours in between so a fault cannot quietly scroll out
of the chat.

## How it speaks

Through the `notifications` table, which the bot drains — the same one sender
for everything, so nothing is delivered twice and the self-check never holds the
bot token.

Except for the one case that breaks: **when the alerting channel is itself the
thing that is down.** A message about a dead bot, queued for that bot, is a
message nobody will ever read. So a failure of `alert:*` escalates to a direct
send, using the token from the secrets file this process can already read. It
exists because the alternative is a silence that looks exactly like health.

Sending outside the bot happens in exactly two places — here, and `sentinel
telegram --send-test`, which the installer runs to prove the channel before
anyone is relying on it. Both go through `telegram/direct.py`, so "did it
actually arrive" is decided once.

## What it never does

It does not restart anything. A self-check that repairs what it finds is a
self-check whose findings you stop reading, and an automatic restart of a
security daemon is a way to turn a visible fault into an intermittent one.
It reports; the operator decides.

## Why a run has to clean up after itself

`selfcheck_state` holds the latest result per check, written by upsert. Upsert
alone only ever adds and updates, so a check that stops being emitted keeps its
last state forever — and if that state was `down`, the panel stays red until
someone deletes the row by hand. That is not hypothetical: `ingest:all` is
emitted only while every source is silent, it fired on 9 August, the sources
came back 85 minutes later, and the operator was told Sentinel was broken for
the following 26 hours.

So a run reconciles: a key present in the table and absent from the run is no
longer a finding, and the row goes. The one case where that would lie is a run
that never reached the check — a crashed group emits none of its keys, and
deleting them would report health that nobody measured. `RunOutcome.complete`
separates the two: a complete run deletes, an incomplete one marks the survivors
`stale` and leaves them alone, to be shown as last-known rather than current.

Withdrawals the operator was told about are announced. They are deliberately not
called a recovery: the runner knows the check stopped producing the finding, and
that is all it knows — the condition may have cleared, or the check may no
longer cover it (a source that fell out of the 30-day window, a unit disabled in
config). Saying the narrower true thing costs one line and cannot be wrong.
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger
from sentinel.selfcheck.checks import CheckResult, run_groups, worst

log = get_logger(__name__)

# A problem that persists is repeated on this cadence. Long enough not to be
# noise, short enough that a fault cannot survive a working day unmentioned.
REALERT_AFTER = timedelta(hours=4)

_EMOJI = {"down": "🔴", "degraded": "🟡", "ok": "🟢", "unknown": "⚪"}


async def run_and_alert(db: Database, cfg: Config, *, quiet: bool = False) -> dict[str, Any]:
    """One pass. Returns a summary for the caller to log or print."""
    started = time.monotonic()
    outcome = await run_groups(db, cfg)
    results = outcome.results
    duration_ms = int((time.monotonic() - started) * 1000)

    previous = await _load_state(db)
    changed_bad: list[CheckResult] = []
    recovered: list[CheckResult] = []
    still_bad: list[CheckResult] = []

    for r in results:
        prev = previous.get(r.key)
        prev_status = prev["status"] if prev else "ok"
        if r.bad and prev_status != r.status:
            changed_bad.append(r)
        elif r.bad:
            due = prev and (
                prev["last_alert_at"] is None
                or _age(prev["last_alert_at"]) > REALERT_AFTER)
            if due:
                still_bad.append(r)
        elif not r.bad and prev_status in ("down", "degraded"):
            recovered.append(r)

    emitted = {r.key for r in results}
    # Only the ones the operator was actually told about. A withdrawn `ok` row
    # is bookkeeping; announcing it would be noise for a non-event. And a run
    # that emitted nothing withdraws nothing — same reason `_reconcile_state`
    # refuses to touch the table in that case.
    withdrawn = [
        prev for key, prev in previous.items()
        if key not in emitted and prev["status"] in ("down", "degraded")
    ] if (outcome.complete and emitted) else []

    await _save_state(db, results, previous)
    await _reconcile_state(db, emitted, complete=outcome.complete)
    await db.execute(
        "INSERT INTO selfcheck_runs (duration_ms, worst_status, checks_run, checks_bad) "
        "VALUES ($1::int, $2::text, $3::int, $4::int)",
        duration_ms, worst(results), len(results), sum(1 for r in results if r.bad))

    announced = changed_bad + still_bad
    if (announced or recovered or withdrawn) and not quiet:
        await _announce(db, cfg, announced, recovered, withdrawn)
        if announced:
            await _mark_alerted(db, [r.key for r in announced])

    return {
        "worst": worst(results),
        "checks": len(results),
        "bad": [r.key for r in results if r.bad],
        "new": [r.key for r in changed_bad],
        "recovered": [r.key for r in recovered],
        "withdrawn": [w["key"] for w in withdrawn],
        "incomplete": list(outcome.failed_groups),
        "duration_ms": duration_ms,
    }


# ---------------------------------------------------------------------------
async def _load_state(db: Database) -> dict[str, dict]:
    rows = await db.fetch(
        "SELECT key, status, title, since, last_alert_at, stale FROM selfcheck_state")
    return {r["key"]: dict(r) for r in rows}


async def _save_state(db: Database, results: list[CheckResult],
                      previous: dict[str, dict]) -> None:
    import json

    for r in results:
        prev = previous.get(r.key)
        # `since` only moves when the status does, so an alert can say how long
        # something has been broken instead of just that it is.
        keep_since = prev is not None and prev["status"] == r.status
        await db.execute(
            """
            INSERT INTO selfcheck_state (key, status, title, detail, facts, since,
                                         last_seen, stale)
            VALUES ($1::text, $2::text, $3::text, $4::text, $5::jsonb, now(), now(), false)
            ON CONFLICT (key) DO UPDATE SET
                status = $2::text, title = $3::text, detail = $4::text, facts = $5::jsonb,
                last_seen = now(), stale = false,
                since = CASE WHEN $6::boolean THEN selfcheck_state.since ELSE now() END
            """,
            r.key, r.status, r.title, r.detail, json.dumps(r.facts), keep_since)


async def _reconcile_state(db: Database, emitted: set[str], *, complete: bool) -> None:
    """Make the table agree with what this run actually produced.

    A key in the table and not in the run is a leftover, not a finding: nobody
    computed it this time, so nobody can vouch for it. On a complete run it is
    deleted — the check withdrew it, and the row would otherwise keep a status
    that no longer has an author. That is the whole bug this exists for.

    On an incomplete run the same rows are kept and flagged, because "the check
    crashed" and "the condition cleared" are indistinguishable from here and
    only one of them is good news. `stale` is what the panel reads to say
    "last known" instead of "current".
    """
    if not emitted:
        # A run with no results at all is not evidence that nothing is wrong;
        # it is evidence that nothing ran. Deleting the entire table on it would
        # be the loudest possible version of this bug.
        log.error("selfcheck produced no results; state left untouched")
        return
    keys = sorted(emitted)
    if complete:
        await db.execute(
            "DELETE FROM selfcheck_state WHERE NOT (key = ANY($1::text[]))", keys)
        return
    await db.execute(
        "UPDATE selfcheck_state SET stale = true "
        "WHERE NOT (key = ANY($1::text[])) AND NOT stale", keys)


async def _mark_alerted(db: Database, keys: list[str]) -> None:
    if keys:
        await db.execute(
            "UPDATE selfcheck_state SET last_alert_at = now() WHERE key = ANY($1::text[])",
            keys)


def _age(moment) -> timedelta:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc) - moment


def _human(delta: timedelta) -> str:
    mins = int(delta.total_seconds() // 60)
    if mins < 60:
        return f"{mins} min"
    if mins < 60 * 48:
        return f"{mins // 60}h {mins % 60}m"
    return f"{mins // 1440} zile"


# ---------------------------------------------------------------------------
def format_alert(bad: list[CheckResult], recovered: list[CheckResult],
                 state: dict[str, dict] | None = None,
                 withdrawn: list[dict] | None = None) -> str:
    """The message. Worst first, and every line says what to do about it."""
    from html import escape

    def esc(v: Any) -> str:
        return escape(str(v), quote=False)

    lines: list[str] = []
    if bad:
        down = [r for r in bad if r.status == "down"]
        head = "🔴 <b>SENTINEL NU FUNCȚIONEAZĂ COMPLET</b>" if down \
            else "🟡 <b>Sentinel funcționează degradat</b>"
        lines.append(head)
        lines.append("")
        for r in sorted(bad, key=lambda x: 0 if x.status == "down" else 1):
            age = ""
            if state and (prev := state.get(r.key)) and prev.get("since"):
                age = f" · de {_human(_age(prev['since']))}"
            lines.append(f"{_EMOJI[r.status]} <b>{esc(r.title)}</b>{age}")
            if r.detail:
                lines.append(f"   {esc(r.detail)}")
            if r.action:
                lines.append(f"   → <code>{esc(r.action)}</code>")
    if recovered:
        if lines:
            lines.append("")
        lines.append("🟢 <b>Revenit la normal</b>")
        for r in recovered:
            lines.append(f"   {esc(r.title)}")
    if withdrawn:
        if lines:
            lines.append("")
        # Not filed under "revenit la normal", and the difference is not
        # pedantry: what is known is that the check no longer produces the
        # finding. Usually the condition cleared; sometimes the check simply
        # stopped covering it (a unit disabled in config, a source past the
        # 30-day window). The age is the age of the finding — never printed as
        # if it were the length of an outage.
        lines.append("⚪ <b>Nu se mai raportează</b>")
        lines.append("   <i>verificarea nu mai produce constatările de mai jos — "
                     "fie condiția a dispărut, fie nu mai sunt acoperite</i>")
        for w in withdrawn:
            age = ""
            if w.get("since"):
                age = f" · constatare veche de {_human(_age(w['since']))}"
            lines.append(f"   {_EMOJI.get(w.get('status'), '⚪')} "
                         f"{esc(w.get('title') or w.get('key'))}{age}")
    lines.append("")
    lines.append("<i>Verificare automată · /selfcheck pentru starea completă</i>")
    return "\n".join(lines)


async def _announce(db: Database, cfg: Config, bad: list[CheckResult],
                    recovered: list[CheckResult],
                    withdrawn: list[dict] | None = None) -> None:
    state = await _load_state(db)
    text = format_alert(bad, recovered, state, withdrawn)
    severity = "critical" if any(r.status == "down" for r in bad) else "high"

    await db.execute(
        """
        INSERT INTO notifications (channel, severity, dedup_key, title, body)
        VALUES ('telegram', $1::text, $2::text, $3::text, $4::text)
        """,
        severity, f"selfcheck:{','.join(sorted(r.key for r in bad))[:180]}",
        "Autoverificare Sentinel", text)

    # If the channel itself is what is broken, queuing is not delivery.
    if any(r.key.startswith("alert:") and r.status == "down" for r in bad):
        await _send_direct(cfg, text)


async def _send_direct(cfg: Config, text: str) -> None:
    """Bypass the bot, once, because the bot is the thing that is down.

    Best-effort by design: this runs when things are already broken, and a
    failure here must not stop the self-check from recording what it found.

    Best-effort is not the same as unverified, though. This used to log
    "selfcheck alerted directly" after any POST that did not raise — a 400 from
    Telegram ("chat not found", "bot was blocked by the user") produced the same
    green line as a delivered message, in the one path that exists for when
    every other path is broken. The per-chat outcome is logged now: a message_id
    is delivery, anything else says which chat and why.
    """
    try:
        from sentinel.config import get_secrets
        from sentinel.telegram.direct import send_to_chats
        from sentinel.telegram.identity import stamp, tag_for

        token = get_secrets().get("TELEGRAM_BOT_TOKEN")
        if not token or not cfg.telegram.allowed_chat_ids:
            return
        # Stamped here because this path exists precisely to skip the bot, and
        # `StampingBot` — which names the instance on everything the bot sends
        # — is skipped with it. This is the one message that arrives when
        # everything else is broken; "which machine" is the first thing it has
        # to answer. See `sentinel/telegram/identity.py`.
        body = stamp(
            "⚠️ <i>trimis direct de autoverificare — botul nu răspunde</i>\n\n" + text,
            tag_for(cfg))
        outcomes = await send_to_chats(
            token, cfg.telegram.allowed_chat_ids, body,
            parse_mode="HTML", timeout_s=15)
        delivered = [o.chat_id for o in outcomes if o.ok]
        failed = [o.describe() for o in outcomes if not o.ok]
        if delivered:
            log.warning("selfcheck alerted directly; the bot is down",
                        extra={"chats": ",".join(str(c) for c in delivered)})
        if failed:
            log.error("direct selfcheck alert did not reach every chat",
                      extra={"detail": "; ".join(failed)})
    except Exception as exc:  # noqa: BLE001
        log.error("direct selfcheck alert failed", extra={"detail": str(exc)})
