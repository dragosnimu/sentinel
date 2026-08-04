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
send, using the token from the secrets file this process can already read. It is
the only place in the codebase that sends outside the bot, and it exists because
the alternative is a silence that looks exactly like health.

## What it never does

It does not restart anything. A self-check that repairs what it finds is a
self-check whose findings you stop reading, and an automatic restart of a
security daemon is a way to turn a visible fault into an intermittent one.
It reports; the operator decides.
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger
from sentinel.selfcheck.checks import CheckResult, run_all, worst

log = get_logger(__name__)

# A problem that persists is repeated on this cadence. Long enough not to be
# noise, short enough that a fault cannot survive a working day unmentioned.
REALERT_AFTER = timedelta(hours=4)

_EMOJI = {"down": "🔴", "degraded": "🟡", "ok": "🟢", "unknown": "⚪"}


async def run_and_alert(db: Database, cfg: Config, *, quiet: bool = False) -> dict[str, Any]:
    """One pass. Returns a summary for the caller to log or print."""
    started = time.monotonic()
    results = await run_all(db, cfg)
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

    await _save_state(db, results, previous)
    await db.execute(
        "INSERT INTO selfcheck_runs (duration_ms, worst_status, checks_run, checks_bad) "
        "VALUES ($1::int, $2::text, $3::int, $4::int)",
        duration_ms, worst(results), len(results), sum(1 for r in results if r.bad))

    announced = changed_bad + still_bad
    if announced and not quiet:
        await _announce(db, cfg, announced, recovered)
        await _mark_alerted(db, [r.key for r in announced])
    elif recovered and not quiet:
        await _announce(db, cfg, [], recovered)

    return {
        "worst": worst(results),
        "checks": len(results),
        "bad": [r.key for r in results if r.bad],
        "new": [r.key for r in changed_bad],
        "recovered": [r.key for r in recovered],
        "duration_ms": duration_ms,
    }


# ---------------------------------------------------------------------------
async def _load_state(db: Database) -> dict[str, dict]:
    rows = await db.fetch(
        "SELECT key, status, since, last_alert_at FROM selfcheck_state")
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
            INSERT INTO selfcheck_state (key, status, title, detail, facts, since, last_seen)
            VALUES ($1::text, $2::text, $3::text, $4::text, $5::jsonb, now(), now())
            ON CONFLICT (key) DO UPDATE SET
                status = $2::text, title = $3::text, detail = $4::text, facts = $5::jsonb,
                last_seen = now(),
                since = CASE WHEN $6::boolean THEN selfcheck_state.since ELSE now() END
            """,
            r.key, r.status, r.title, r.detail, json.dumps(r.facts), keep_since)


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
                 state: dict[str, dict] | None = None) -> str:
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
    lines.append("")
    lines.append("<i>Verificare automată · /selfcheck pentru starea completă</i>")
    return "\n".join(lines)


async def _announce(db: Database, cfg: Config, bad: list[CheckResult],
                    recovered: list[CheckResult]) -> None:
    state = await _load_state(db)
    text = format_alert(bad, recovered, state)
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
    """
    try:
        import httpx

        from sentinel.config import get_secrets

        token = get_secrets().get("TELEGRAM_BOT_TOKEN")
        if not token or not cfg.telegram.allowed_chat_ids:
            return
        async with httpx.AsyncClient(timeout=15) as client:
            for chat_id in cfg.telegram.allowed_chat_ids:
                await client.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": chat_id, "parse_mode": "HTML",
                          "text": "⚠️ <i>trimis direct de autoverificare — "
                                  "botul nu răspunde</i>\n\n" + text})
        log.warning("selfcheck alerted directly; the bot is down")
    except Exception as exc:  # noqa: BLE001
        log.error("direct selfcheck alert failed", extra={"detail": str(exc)})
