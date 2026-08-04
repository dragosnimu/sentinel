"""The Telegram bot: reporting, incident push, and manual response.

Reporting was P4; P5 added response. The bot can now block, unblock and flush —
each behind an explicit confirmation and role check (owner/operator act, viewer
is read-only). Patch approval and its own confirmation flow arrive in P9. Every
update is checked against the chat-id allowlist before anything runs; an
unauthorised chat gets silence and one log line, never a reply that would confirm
the bot exists.

Incident pushes for a network actor carry a one-tap block button. Tapping it is
routed through the same on_callback path as /block, so the role check and the
executor's never-block guard both still apply — a viewer's tap and an admin
address are both refused.

Push is a plain asyncio task, not the PTB job-queue, so the base
python-telegram-bot install (no [job-queue] extra) is enough. It polls for
incidents the operator has not been told about yet and sends them.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from sentinel import __version__
from sentinel.config import Config, Secrets
from sentinel.db.engine import Database
from sentinel.db.repo import assets as assets_repo
from sentinel.db.repo import blocklist as blocklist_repo
from sentinel.db.repo import capacity as capacity_repo
from sentinel.db.repo import health as health_repo
from sentinel.db.repo import incidents as inc_repo
from sentinel.errors import ExecutorRejected, ExecutorUnavailable
from sentinel.logging_setup import get_logger
from sentinel.respond import actions

log = get_logger(__name__)

_SEV_EMOJI = {"info": "⚪", "low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}
_STATUS_EMOJI = {"up": "🟢", "degraded": "🟡", "down": "🔴", "unknown": "⚪"}


def _esc(text: Any) -> str:
    return html.escape(str(text)) if text is not None else ""


def _authorized(cfg: Config, update: Update) -> bool:
    chat = update.effective_chat
    return chat is not None and chat.id in set(cfg.telegram.allowed_chat_ids)


def _can_act(cfg: Config, chat_id: int) -> bool:
    """Owner or operator may block/unblock. A viewer is read-only.

    If no roles are configured (only allowed_chat_ids), every allowed chat can
    act — a single-admin deployment should not have to also list itself as owner.
    """
    tg = cfg.telegram
    if tg.owner_chat_id is None and not tg.operator_chat_ids:
        return chat_id in set(tg.allowed_chat_ids)
    return chat_id == tg.owner_chat_id or chat_id in set(tg.operator_chat_ids)


async def _deny_viewer(update: Update) -> None:
    await update.effective_message.reply_text(
        "Această comandă modifică starea (blocare/deblocare) și necesită rol de "
        "operator sau owner. Contul tău are acces doar de vizualizare."
    )


def _guard(handler):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        cfg: Config = context.bot_data["cfg"]
        if not _authorized(cfg, update):
            chat = update.effective_chat
            log.warning("unauthorized telegram command",
                        extra={"chat_id": chat.id if chat else None})
            return
        try:
            await handler(update, context)
        except Exception as exc:  # noqa: BLE001 - a broken command must not kill the bot
            log.error("telegram handler failed", extra={"detail": str(exc)})
            if update.message:
                await update.message.reply_text("A apărut o eroare la procesarea comenzii.")
    return wrapper


# --- formatting ------------------------------------------------------------
def format_incident(inc: inc_repo.IncidentRow, *, header: str = "INCIDENT") -> str:
    # An IDS rule is named after what it detects, so the CVE is usually sitting
    # in the title: "ET EXPLOIT Apache log4j RCE CVE-2021-44228". Linking it is
    # the difference between an alert you can act on from a phone and one that
    # needs a laptop and a search engine.
    from sentinel.intel.links import cve_html, cves_in

    emoji = _SEV_EMOJI.get(inc.severity, "⚪")
    lines = [
        f"{emoji} <b>{header} #{inc.id}</b> · <b>{_esc(inc.severity.upper())}</b>",
        f"<b>{_esc(inc.title)}</b>",
    ]
    if inc.summary:
        lines.append(_esc(inc.summary))
    if inc.actor_key:
        lines.append(f"Sursă: <code>{_esc(inc.actor_key)}</code>")
    # One references line rather than links woven into the title. The title is
    # read first and fastest; turning words inside it blue costs more than the
    # tap it saves, and the same CVE would then appear twice on one card.
    refs = cves_in(f"{inc.title} {inc.summary or ''}")[:3]
    if refs:
        lines.append("Referințe: " + " · ".join(cve_html(c) for c in refs))
    lines.append(f"Detecții: {inc.detection_count} · stare: {_esc(inc.status)}")
    auto = _auto_action_text(inc.auto_action)
    if auto:
        lines.append(auto)
    lines.append(f"Detalii: <code>/incident {inc.id}</code>")
    return "\n".join(lines)


_SKIP_REASON_RO = {
    "rate_cap": "plafon de rată atins",
    "max_elements": "blocklist plin",
    "allowlisted": "sursă în allowlist",
    "known_scanner": "scanner cunoscut",
    "cidr_not_allowed": "bloc CIDR nepermis",
    "refused_client": "refuzat la validare",
    "executor_error": "executor indisponibil",
}


def _auto_action_text(auto_action: str | None) -> str | None:
    """Render the decider's verdict for the alert body."""
    if not auto_action or auto_action == "observed":
        return None
    if auto_action == "blocked":
        return "🛡️ <b>Blocat automat</b>"
    if auto_action.startswith("skipped:"):
        reason = _SKIP_REASON_RO.get(auto_action[8:], auto_action[8:])
        return f"⏭️ Auto-block sărit: {_esc(reason)}"
    return None


def _incident_ip(inc: inc_repo.IncidentRow) -> str | None:
    """The attacker IP if the incident has one. actor_key defaults to src_ip,
    so for the network rules it is the address — but only trust it if it really
    parses as one, never as a label to shove into a block command."""
    if not inc.actor_key:
        return None
    try:
        ipaddress.ip_address(inc.actor_key)
    except ValueError:
        return None
    return inc.actor_key


def _incident_block_kb(inc: inc_repo.IncidentRow, cfg: Config) -> InlineKeyboardMarkup | None:
    """The one-tap action on the alert. If the decider already blocked the actor
    (armed mode), offer UNBLOCK; otherwise offer BLOCK. Either way on_callback
    re-checks the role and the executor re-checks never-block, so a viewer's tap
    is refused and the admin address is never firewalled even if pressed."""
    ip = _incident_ip(inc)
    if ip is None:
        return None
    if inc.auto_action == "blocked":
        return InlineKeyboardMarkup([[
            InlineKeyboardButton(f"↩️ Deblochează {ip}", callback_data=f"unblk:{ip}"),
            InlineKeyboardButton("✔️ OK, lasă blocat", callback_data="cancel"),
        ]])
    ttl = cfg.response.auto_block.default_ttl_s
    hours = ttl // 3600
    label = f"🚫 Blochează {ip}" + (f" ({hours}h)" if ttl else " (permanent)")
    return InlineKeyboardMarkup([[
        InlineKeyboardButton(label, callback_data=f"blk:{ip}:{ttl}"),
        InlineKeyboardButton("❌ Ignoră", callback_data="cancel"),
    ]])


# --- commands --------------------------------------------------------------
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db: Database = context.bot_data["db"]
    counts = await inc_repo.open_counts(db)
    live = await health_repo.live_status(db)
    assets = await assets_repo.list_all(db)
    up = sum(1 for a in assets if (s := live.get(a.id)) and s.status == "up")
    down = sum(1 for a in assets if (s := live.get(a.id)) and s.status == "down")

    sev_line = " ".join(
        f"{_SEV_EMOJI[s]}{counts[s]}" for s in ("critical", "high", "medium", "low") if counts.get(s)
    ) or "niciun incident deschis"
    text = (
        f"🛡️ <b>Sentinel {_esc(__version__)}</b>\n"
        f"Incidente deschise: <b>{counts['total']}</b>  {sev_line}\n"
        f"Servicii: 🟢 {up} active · 🔴 {down} picate · {len(assets)} total\n"
        f"Toate comenzile: /ajutor"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_incidents(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db: Database = context.bot_data["db"]
    rows = await inc_repo.list_incidents(db, status="open", limit=10)
    if not rows:
        await update.message.reply_text("Niciun incident deschis. 🎉")
        return
    blocks = [format_incident(r) for r in rows]
    await update.message.reply_text("\n\n".join(blocks), parse_mode=ParseMode.HTML)


async def cmd_patches(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """`/patches` — list plans awaiting a decision, `/patch <id>` to see one."""
    from sentinel.db.repo import patches as patch_repo
    from sentinel.telegram import patch_flow

    db: Database = context.bot_data["db"]
    cfg: Config = context.bot_data["cfg"]

    if context.args and context.args[0].isdigit():
        row = await patch_repo.get_plan(db, int(context.args[0]))
        if row is None:
            await update.message.reply_text("Plan inexistent.")
            return
        if row.status != "validated":
            await update.message.reply_text(
                patch_flow.format_plan(row) + f"\n\nStare: <b>{row.status}</b> — "
                "nu poate fi aprobat.", parse_mode=ParseMode.HTML)
            return
        if not _can_act(cfg, update.effective_chat.id):
            await update.message.reply_text(patch_flow.format_plan(row),
                                            parse_mode=ParseMode.HTML)
            return
        await patch_flow.send_plan_for_approval(
            context.bot, db, update.effective_chat.id, row)
        return

    rows = await patch_repo.list_plans(db, limit=10)
    pending = [r for r in rows if r.status == "validated"]
    if not pending:
        await update.message.reply_text(
            "Niciun plan de patch în așteptare." if not rows else
            "Niciun plan validat în așteptare.\nUltimele: "
            + ", ".join(f"#{r.id} ({r.status})" for r in rows[:5]))
        return
    lines = ["🩹 <b>Planuri în așteptare</b>"]
    for r in pending:
        target = r.plan.get("target", {}).get("asset_name", "?")
        lines.append(f"• #{r.id} — {_esc(target)} · risc {_esc(r.risk_level or '?')} "
                     f"· <code>/patch {r.id}</code>")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def on_patch_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Route every patch button. Role is checked here, once, before any branch —
    a viewer must not be able to dry-run either, since that still runs commands."""
    cfg: Config = context.bot_data["cfg"]
    query = update.callback_query

    if not _authorized(cfg, update) or not _can_act(cfg, update.effective_chat.id):
        # An alert, not an edit. Editing would delete the plan and its buttons
        # for everyone in the chat because one viewer tapped something.
        await query.answer("Neautorizat.", show_alert=True)
        return
    await query.answer()

    from sentinel.telegram import patch_flow
    data = query.data or ""
    prefix, _, rest = data.partition(":")
    try:
        if prefix == "pap1":
            await patch_flow.on_stage1(update, context, rest)
        elif prefix == "pap2":
            await patch_flow.on_stage2(update, context, rest)
        elif prefix == "pdry":
            await patch_flow.on_dry_run(update, context, int(rest))
        elif prefix == "prej":
            await patch_flow.on_reject(update, context, int(rest))
    except Exception as exc:  # noqa: BLE001 - never leave the operator staring at a spinner
        log.error("patch callback failed", extra={"data": prefix, "detail": str(exc)})
        # Reply, never edit. An unexpected exception is the worst moment to
        # destroy the message holding the plan and the only approval buttons.
        await query.message.reply_text(f"Eroare: {_esc(exc)}")


async def _close_incident(update: Update, context: ContextTypes.DEFAULT_TYPE,
                          status: str, label: str) -> None:
    """Shared body for /resolve and /fp.

    The status is a parameter rather than shared state: `bot_data` is global
    across every chat, so stashing it there would let two operators acting at
    the same moment swap each other's verdict.
    """
    cfg: Config = context.bot_data["cfg"]
    if not _can_act(cfg, update.effective_chat.id):
        await update.message.reply_text("Doar owner/operator pot închide incidente.")
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text(
            "Folosire: <code>/resolve &lt;id&gt; [notă]</code>\n"
            "sau <code>/fp &lt;id&gt;</code> pentru fals-pozitiv.",
            parse_mode=ParseMode.HTML)
        return

    db: Database = context.bot_data["db"]
    incident_id = int(context.args[0])
    note = " ".join(context.args[1:])[:300] or None

    inc = await inc_repo.get_incident(db, incident_id)
    if inc is None:
        await update.message.reply_text("Incident inexistent.")
        return
    await inc_repo.set_status(db, incident_id, status, note=note,
                              by=f"telegram:{update.effective_chat.id}")
    await update.message.reply_text(
        f"✅ Incident #{incident_id} marcat <b>{label}</b>.\n<i>{_esc(inc.title)}</i>",
        parse_mode=ParseMode.HTML)


async def cmd_resolve(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """`/resolve <id> [notă]` — close an incident from the phone that alerted you.

    The alert arrives here, so the dismissal belongs here too: making someone
    open a laptop to clear a known-benign incident is how a queue stops being read.
    """
    await _close_incident(update, context, "resolved", "rezolvat")


async def cmd_false_positive(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """`/fp <id>` — closes it too, but records that the RULE was wrong. That
    number is the one worth watching when deciding which threshold to relax."""
    await _close_incident(update, context, "false_positive", "fals-pozitiv")


async def cmd_incident(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db: Database = context.bot_data["db"]
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Folosire: <code>/incident &lt;id&gt;</code>", parse_mode=ParseMode.HTML)
        return
    inc = await inc_repo.get_incident(db, int(context.args[0]))
    if inc is None:
        await update.message.reply_text("Incident inexistent.")
        return
    dets = await inc_repo.incident_detections(db, inc.id, limit=5)
    text = format_incident(inc)
    if dets:
        det_lines = "\n".join(
            f"• {_esc(d['ts'].strftime('%H:%M:%S'))} {_esc(d['rule_id'])} [{_esc(d['severity'])}]"
            for d in dets
        )
        text += f"\n\n<b>Detecții recente</b>\n{det_lines}"
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_services(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db: Database = context.bot_data["db"]
    assets = await assets_repo.list_all(db)
    live = await health_repo.live_status(db)
    lines = ["🖥️ <b>Servicii</b>"]
    for a in assets:
        s = live.get(a.id)
        status = s.status if s else "unknown"
        lat = f" {s.latency_ms}ms" if s and s.latency_ms is not None else ""
        lines.append(f"{_STATUS_EMOJI.get(status, '⚪')} {_esc(a.name)}{lat}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db: Database = context.bot_data["db"]
    cap = await capacity_repo.latest(db)
    if cap is None:
        await update.message.reply_text("Nicio măsurătoare de capacitate încă.")
        return
    disks = " · ".join(f"{_esc(m)} {d['used_pct']}%" for m, d in cap.disks.items())
    text = (
        f"📊 <b>Capacitate</b>\n"
        f"CPU: {cap.cpu_pct}% · încărcare: {cap.load1}\n"
        f"RAM disponibil: {cap.mem_available_mb} MB / {cap.mem_total_mb}\n"
        f"Disc: {disks}\n"
        f"Conexiuni TCP: {cap.conn_count}"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# --- response commands (P5) -----------------------------------------------
from sentinel.telegram.bot_ttl import parse_ttl as _parse_ttl  # noqa: E402


async def cmd_block(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: Config = context.bot_data["cfg"]
    if not _can_act(cfg, update.effective_chat.id):
        await _deny_viewer(update)
        return
    if not context.args:
        await update.message.reply_text(
            "Folosire: <code>/block &lt;ip&gt; [durată: 1h|30m|3600|perm]</code>",
            parse_mode=ParseMode.HTML)
        return
    ip = context.args[0]
    ttl = _parse_ttl(context.args[1] if len(context.args) > 1 else None)
    ttl_label = "permanent" if ttl is None else (f"{ttl // 3600}h" if ttl >= 3600 else f"{ttl}s")

    # Confirm before acting. A block is reversible, but a fat-fingered address is
    # still an outage for whoever is behind it, so it gets a second tap.
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton(f"✅ Blochează {ip} ({ttl_label})", callback_data=f"blk:{ip}:{ttl if ttl is not None else 0}"),
        InlineKeyboardButton("❌ Anulează", callback_data="cancel"),
    ]])
    await update.message.reply_text(
        f"Confirmi blocarea <code>{_esc(ip)}</code> pentru {ttl_label}?",
        parse_mode=ParseMode.HTML, reply_markup=kb)


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: Config = context.bot_data["cfg"]
    query = update.callback_query
    await query.answer()
    if not _authorized(cfg, update) or not _can_act(cfg, update.effective_chat.id):
        await query.edit_message_text("Neautorizat.")
        return
    data = query.data or ""
    if data == "cancel":
        await query.edit_message_text("Anulat.")
        return
    if data.startswith("unblk:"):
        ip = data.split(":", 1)[1]
        db = context.bot_data["db"]
        try:
            await actions.unblock(db, ip, by=f"telegram:{update.effective_chat.id}")
            await query.edit_message_text(
                f"↩️ Deblocat <code>{_esc(ip)}</code>.", parse_mode=ParseMode.HTML)
        except Exception as exc:  # noqa: BLE001
            await query.edit_message_text(f"Nu am putut debloca: {_esc(exc)}")
        return
    if data.startswith("blk:"):
        _, ip, ttl_s = data.split(":", 2)
        ttl = int(ttl_s) or None
        db: Database = context.bot_data["db"]
        by = f"telegram:{update.effective_chat.id}"
        try:
            await actions.block(db, ip, ttl=ttl, reason="blocare manuală Telegram", by=by)
            await query.edit_message_text(f"🛡️ Blocat <code>{_esc(ip)}</code>.", parse_mode=ParseMode.HTML)
        except actions.BlockRefused as exc:
            await query.edit_message_text(f"Refuzat: {_esc(exc)}")
        except ExecutorRejected as exc:
            await query.edit_message_text(f"Executorul a refuzat: {_esc(exc)}")
        except ExecutorUnavailable as exc:
            await query.edit_message_text(f"Executorul e indisponibil: {_esc(exc)}")


async def cmd_unblock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: Config = context.bot_data["cfg"]
    if not _can_act(cfg, update.effective_chat.id):
        await _deny_viewer(update)
        return
    if not context.args:
        await update.message.reply_text("Folosire: <code>/unblock &lt;ip&gt;</code>", parse_mode=ParseMode.HTML)
        return
    ip = context.args[0]
    db: Database = context.bot_data["db"]
    try:
        await actions.unblock(db, ip, by=f"telegram:{update.effective_chat.id}")
        await update.message.reply_text(f"Deblocat <code>{_esc(ip)}</code>.", parse_mode=ParseMode.HTML)
    except (ExecutorRejected, ExecutorUnavailable) as exc:
        await update.message.reply_text(f"Eroare: {_esc(exc)}")


async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """`/mute` — set, inspect or clear the quiet window for THIS chat.

    Per chat, not global: the operator typing it is the one being woken up, and
    a shared setting would let one person silence another's phone.
    """
    from datetime import datetime, timezone as _tz

    from sentinel.db.repo import chats as chats_repo
    from sentinel.telegram import quiet

    cfg: Config = context.bot_data["cfg"]
    db: Database = context.bot_data["db"]
    chat_id = update.effective_chat.id

    if not _can_act(cfg, chat_id):
        await _deny_viewer(update)
        return

    arg = " ".join(context.args or []).strip()
    prefs = await chats_repo.get_prefs(db, chat_id)
    tz_name = prefs.timezone or getattr(cfg.telegram, "timezone", None)

    # --- status ---
    if not arg:
        window = quiet.parse_window(prefs.quiet_hours or cfg.telegram.quiet_hours or "")
        state = quiet.evaluate(now=datetime.now(_tz.utc), window=window,
                               muted_until=prefs.muted_until, tz_name=tz_name)
        lines = [_MUTE_HELP, ""]
        lines.append(f"Interval: <b>{window or 'niciunul'}</b>")
        if prefs.muted_until and prefs.muted_until > datetime.now(_tz.utc):
            lines.append(f"Pauză activă până la <b>{_fmt_local(prefs.muted_until, tz_name)}</b>")
        lines.append(
            f"Acum: <b>{'🔕 liniște' if state.muted else '🔔 activ'}</b>"
            + (f" — {_esc(state.reason)}, până la {_fmt_local(state.until, tz_name)}"
               if state.muted and state.until else ""))
        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)
        return

    # --- off ---
    if arg.lower() in ("off", "stop", "0", "nu", "gata"):
        await chats_repo.clear_all_mutes(db, chat_id)
        log.warning("quiet hours cleared", extra={"chat_id": chat_id})
        await update.message.reply_text("🔔 Alertele sunt active. Niciun interval de liniște.")
        return

    # --- recurring window ---
    if (window := quiet.parse_window(arg)) is not None:
        await chats_repo.set_quiet_hours(db, chat_id, str(window), tz=tz_name)
        log.warning("quiet hours set", extra={"chat_id": chat_id, "window": str(window)})
        crosses = " (peste miezul nopții)" if window.crosses_midnight else ""
        await update.message.reply_text(
            f"🔕 Liniște în fiecare zi între <b>{window}</b>{crosses}.\n"
            f"Fus orar: <code>{_esc(str(quiet.zone(tz_name)))}</code>\n\n"
            "<i>Criticele, PANIC și eșecurile de patch trec oricum. "
            "Restul sosesc la sfârșitul intervalului.</i>",
            parse_mode=ParseMode.HTML)
        return

    # --- ad-hoc ---
    if (delta := quiet.parse_duration(arg)) is not None:
        until = datetime.now(_tz.utc) + delta
        await chats_repo.set_muted_until(db, chat_id, until)
        log.warning("ad-hoc mute set", extra={"chat_id": chat_id, "minutes": delta.total_seconds() / 60})
        capped = " (limitat la 24h)" if delta >= quiet.MAX_ADHOC else ""
        await update.message.reply_text(
            f"🔕 Pauză până la <b>{_fmt_local(until, tz_name)}</b>{capped}.",
            parse_mode=ParseMode.HTML)
        return

    await update.message.reply_text(
        "Nu am înțeles.\n\n" + _MUTE_HELP, parse_mode=ParseMode.HTML)


async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.args = ["off"]
    await cmd_mute(update, context)


async def cmd_panic(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: Config = context.bot_data["cfg"]
    if not _can_act(cfg, update.effective_chat.id):
        await _deny_viewer(update)
        return
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("🚨 Golește TOT blocklistul", callback_data="flush"),
        InlineKeyboardButton("❌ Anulează", callback_data="cancel"),
    ]])
    await update.message.reply_text(
        "Confirmi golirea întregului blocklist? (deblochează toate IP-urile)", reply_markup=kb)


async def on_flush_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cfg: Config = context.bot_data["cfg"]
    query = update.callback_query
    await query.answer()
    if not _can_act(cfg, update.effective_chat.id):
        await query.edit_message_text("Neautorizat.")
        return
    db: Database = context.bot_data["db"]
    try:
        await actions.flush(db, by=f"telegram:{update.effective_chat.id}", reason="panic Telegram")
        await query.edit_message_text("🚨 Blocklist golit.")
    except (ExecutorRejected, ExecutorUnavailable) as exc:
        await query.edit_message_text(f"Eroare: {_esc(exc)}")


# --- push loop -------------------------------------------------------------
_EXEC_EMOJI = {"succeeded": "✅", "aborted": "⛔", "failed": "❌",
               "rolled_back": "↩️", "rollback_failed": "🔥"}


def _format_execution(row: dict) -> str:
    """The outcome of a run the operator started somewhere else.

    A dry-run that succeeded is good news and gets one line. Anything that rolled
    back or failed carries its reason: that is the whole reason to send this.
    """
    mode = "Dry-run" if row["mode"] == "dry_run" else "Aplicare"
    emoji = _EXEC_EMOJI.get(row["status"], "•")
    lines = [
        f"{emoji} <b>{mode} {_esc(row['status'])}</b> · plan #{row['plan_id']} "
        f"(execuție #{row['id']})",
        f"Pornit de: <code>{_esc(row['triggered_by'])}</code>",
    ]
    if row.get("duration_ms"):
        lines.append(f"Durată: {row['duration_ms']} ms")
    if row.get("rollback_reason"):
        lines.append(f"\n↩️ <b>Revenire:</b> {_esc(str(row['rollback_reason'])[:300])}")
    elif row.get("error"):
        lines.append(f"\n<b>Eroare:</b> {_esc(str(row['error'])[:300])}")
    if row["mode"] == "dry_run":
        lines.append("\n<i>Nimic nu a fost modificat.</i>")
    return "\n".join(lines)


async def _quiet_chats(cfg: Config, db: Database) -> set[int]:
    """Chats that are inside a quiet window right now.

    Read once per cycle. A per-message lookup would query this table thousands
    of times a day to answer a question that changes twice.
    """
    from datetime import datetime, timezone as _tz

    from sentinel.db.repo import chats as chats_repo
    from sentinel.telegram import quiet

    now = datetime.now(_tz.utc)
    prefs = await chats_repo.all_prefs(db)
    default = cfg.telegram.quiet_hours
    out: set[int] = set()
    for chat_id in cfg.telegram.allowed_chat_ids:
        p = prefs.get(chat_id)
        window = quiet.parse_window((p.quiet_hours if p else None) or default or "")
        state = quiet.evaluate(now=now, window=window,
                               muted_until=p.muted_until if p else None,
                               tz_name=(p.timezone if p else None)
                               or getattr(cfg.telegram, "timezone", None))
        if state.muted:
            out.add(chat_id)
    return out


async def _broadcast(app: Application, cfg: Config, text: str,
                     kb: InlineKeyboardMarkup | None = None, *,
                     quiet_chats: set[int] | None = None,
                     severity: str | None = None, kind: str | None = None) -> int:
    """Send to every allowed chat. Returns how many actually went out.

    A chat inside its quiet window is skipped — unless the message is one that
    is never muted, in which case the window is ignored entirely. See
    `telegram/quiet.py` for what qualifies and why.
    """
    from sentinel.telegram.quiet import passes_anyway

    urgent = passes_anyway(severity, kind)
    sent = 0
    for chat_id in cfg.telegram.allowed_chat_ids:
        if quiet_chats and chat_id in quiet_chats and not urgent:
            continue
        try:
            await app.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML,
                                       reply_markup=kb)
            sent += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("push send failed", extra={"chat_id": chat_id, "detail": str(exc)})
    return sent


# More than this many incidents waiting when the window lifts, and they arrive
# as one summary instead of one message each. Waking up to sixty notifications
# is functionally the same as waking up to none.
DIGEST_FLOOR = 6


async def _push_incidents(app: Application, cfg: Config, db: Database,
                          quiet_chats: set[int]) -> None:
    pending = await inc_repo.unnotified(db, min_severity=cfg.telegram.min_severity)
    if not pending:
        return

    # Everyone quiet and nothing urgent in the batch: leave the rows unsent.
    # They are HELD, not dropped — `notified_at` stays NULL, so the next cycle
    # after the window lifts picks them all up.
    all_quiet = quiet_chats >= set(cfg.telegram.allowed_chat_ids)
    from sentinel.telegram.quiet import passes_anyway

    if all_quiet and not any(passes_anyway(i.severity) for i in pending):
        log.info("incidents held for quiet hours", extra={"n": len(pending)})
        return

    threshold = max(getattr(cfg.telegram, "digest_threshold", 10), DIGEST_FLOOR)
    if len(pending) > threshold:
        await _push_incident_digest(app, cfg, db, pending, quiet_chats)
        return

    for inc in pending:
        text = "🚨 " + format_incident(inc, header="INCIDENT NOU")
        await _broadcast(app, cfg, text, _incident_block_kb(inc, cfg),
                         quiet_chats=quiet_chats, severity=inc.severity)
        await inc_repo.mark_notified(db, inc.id)
        log.info("incident pushed", extra={"incident_id": inc.id, "severity": inc.severity})


async def _push_incident_digest(app: Application, cfg: Config, db: Database,
                                pending: list, quiet_chats: set[int]) -> None:
    """One message for a backlog, which is what a night of quiet hours produces."""
    by_sev: dict[str, int] = {}
    for inc in pending:
        by_sev[inc.severity] = by_sev.get(inc.severity, 0) + 1
    summary = " · ".join(f"{n} {sev}" for sev, n in sorted(by_sev.items()))
    lines = [f"📋 <b>{len(pending)} incidente noi</b> — {summary}", ""]
    for inc in pending[:10]:
        lines.append(f"{_SEV_EMOJI.get(inc.severity, '⚪')} #{inc.id} "
                     f"{_esc(inc.title)} · <code>{_esc(inc.actor_key or '—')}</code>")
    if len(pending) > 10:
        lines.append(f"<i>…și încă {len(pending) - 10}.</i>")
    lines.append("\nDeschide unul: <code>/incident &lt;id&gt;</code>")

    await _broadcast(app, cfg, "\n".join(lines), quiet_chats=quiet_chats,
                     severity=max((i.severity for i in pending), key=_sev_rank, default=None))
    for inc in pending:
        await inc_repo.mark_notified(db, inc.id)
    log.warning("incident digest pushed", extra={"n": len(pending)})


def _sev_rank(sev: str) -> int:
    return ["info", "low", "medium", "high", "critical"].index(sev) if sev in (
        "info", "low", "medium", "high", "critical") else 0


async def _push_plans(app: Application, cfg: Config, db: Database,
                     quiet_chats: set[int]) -> None:
    """Offer newly generated plans, with their approval buttons.

    Unlike an incident, this is NOT marked notified when every send failed. An
    incident that missed its push is still visible in the dashboard and still
    counted; a plan that missed its push is a decision waiting on someone who was
    never asked. It is retried until it either lands or ages out of the TTL.

    Quiet hours hold plans rather than dropping them, and that falls out of the
    same rule: nothing is marked notified until it reaches somebody. A patch
    proposal is the least urgent thing here — it changes a production machine
    and needs two confirmations — so it can wait for morning.
    """
    from sentinel.db.repo import patches as patch_repo
    from sentinel.telegram import patch_flow

    for row in await patch_repo.unnotified_plans(db):
        sent = 0
        for chat_id in cfg.telegram.allowed_chat_ids:
            # Not _broadcast: each chat needs its OWN approval token, because a
            # token is bound to the chat it was issued for.
            if not _can_act(cfg, chat_id) or chat_id in quiet_chats:
                continue
            try:
                await patch_flow.send_plan_for_approval(app.bot, db, chat_id, row)
                sent += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("plan push failed",
                            extra={"chat_id": chat_id, "plan": row.id, "detail": str(exc)})
        if sent:
            await patch_repo.mark_plan_notified(db, row.id)
            log.warning("patch plan pushed", extra={"plan": row.id, "chats": sent})
        else:
            log.error("patch plan reached nobody — will retry",
                      extra={"plan": row.id})


async def _push_executions(app: Application, cfg: Config, db: Database,
                          quiet_chats: set[int]) -> None:
    from sentinel.db.repo import patches as patch_repo

    for row in await patch_repo.unnotified_executions(db):
        # A patch that failed or rolled back is never held: something on the
        # host changed and then changed back, and that does not keep till
        # morning. A clean dry-run does.
        kind = ("patch_rolled_back" if row["status"] in ("rolled_back", "rollback_failed")
                else "patch_failed" if row["status"] == "failed" else None)
        await _broadcast(app, cfg, _format_execution(row),
                         quiet_chats=quiet_chats, kind=kind)
        # Marked whatever happened: an outcome report is information, not a
        # pending decision, and retrying it forever would be noise.
        await patch_repo.mark_execution_notified(db, row["id"])
        log.info("execution outcome pushed",
                 extra={"execution_id": row["id"], "status": row["status"]})


async def _push_notifications(app: Application, cfg: Config, db: Database,
                              quiet_chats: set[int]) -> None:
    """Drain the generic notification queue.

    Currently fed by the self-check. Kept generic because the table always was:
    anything that needs to tell the operator something, without holding the bot
    token itself, writes a row here.
    """
    rows = await db.fetch(
        "SELECT id, severity, title, body FROM notifications "
        "WHERE state = 'queued' AND channel = 'telegram' "
        "ORDER BY enqueued_at LIMIT 5")
    for row in rows:
        # `selfcheck` is never held: the message says part of the security agent
        # has stopped working, and that does not keep until morning.
        sent = await _broadcast(app, cfg, row["body"], quiet_chats=quiet_chats,
                                severity=row["severity"], kind="selfcheck")
        await db.execute(
            "UPDATE notifications SET state = $2::text, sent_at = now(), "
            "attempts = attempts + 1 WHERE id = $1",
            row["id"], "sent" if sent else "failed")
        log.warning("notification pushed",
                    extra={"id": row["id"], "severity": row["severity"], "chats": sent})


async def _push_loop(app: Application, cfg: Config, db: Database) -> None:
    interval = 15
    # Each source is isolated: a failure in one must not stop the others. An
    # exception in the plan query used to be enough to stop incident alerts.
    sources = (("incidents", _push_incidents), ("plans", _push_plans),
               ("executions", _push_executions),
               ("notifications", _push_notifications))
    while True:
        # Resolved once per cycle and handed to each source, so all three agree
        # on whether it is quiet — and so a slow cycle cannot straddle the end
        # of the window and send half the batch under the old answer.
        try:
            quiet_chats = await _quiet_chats(cfg, db)
        except Exception as exc:  # noqa: BLE001
            # Failing OPEN is the only safe direction: a broken preferences
            # query must not silence a security channel.
            log.error("quiet-hours lookup failed; alerting anyway",
                      extra={"detail": str(exc)})
            quiet_chats = set()

        for name, fn in sources:
            try:
                await fn(app, cfg, db, quiet_chats)
            except Exception as exc:  # noqa: BLE001
                log.error("push loop error", extra={"source": name, "detail": str(exc)})
        await asyncio.sleep(interval)


def build_application(cfg: Config, secrets: Secrets) -> Application:
    token = secrets.require("TELEGRAM_BOT_TOKEN")
    app = Application.builder().token(token).build()

    async def post_init(application: Application) -> None:
        db = Database(cfg)
        await db.connect()
        application.bot_data["db"] = db
        application.bot_data["cfg"] = cfg
        application.bot_data["push_task"] = asyncio.create_task(_push_loop(application, cfg, db))
        log.info("telegram bot ready", extra={"chats": len(cfg.telegram.allowed_chat_ids)})

    async def post_shutdown(application: Application) -> None:
        task = application.bot_data.get("push_task")
        if task:
            task.cancel()
        db = application.bot_data.get("db")
        if db:
            await db.close()

    app.post_init = post_init
    app.post_shutdown = post_shutdown

    from sentinel.telegram import views

    # Every command, and the Romanian name for each one. The interface language
    # is Romanian, so `/incidente` has to work; the English names stay because
    # they are what the documentation and the phone's autocomplete already
    # learned, and dropping them would break both.
    #
    # (name, handler) — registered for each alias in the tuple.
    read_only = [
        (("start", "help", "ajutor"),                  views.cmd_help),
        (("dashboard", "panou"),                       views.cmd_dashboard),
        (("status",),                                  cmd_status),
        (("incidents", "incidente"),                   cmd_incidents),
        (("incident",),                                cmd_incident),
        # No diacritics: Telegram accepts [a-z0-9_] in a command name and
        # REJECTS the whole handler set otherwise, which crash-loops the bot —
        # i.e. one bad alias takes down the emergency channel.
        (("vulns", "vulnerabilitati"),                 views.cmd_vulns),
        (("vuln",),                                    views.cmd_vuln),
        (("events", "evenimente"),                     views.cmd_events),
        (("services", "servicii"),                     cmd_services),
        (("health", "sanatate"),                       cmd_health),
        (("selfcheck", "autoverificare"),              views.cmd_selfcheck),
        (("blocklist", "blocate"),                     views.cmd_blocklist_full),
        (("patches", "patch", "patchuri"),             cmd_patches),
    ]
    for names, handler in read_only:
        for name in names:
            app.add_handler(CommandHandler(name, _guard(handler)))

    # State-changing. Each re-checks the role itself; `_guard` only enforces the
    # chat allowlist, which is not the same thing.
    acting = [
        (("resolve", "rezolva"),   cmd_resolve),
        (("fp", "falspozitiv"),    cmd_false_positive),
        (("block", "blocheaza"),   cmd_block),
        (("unblock", "deblocheaza"), cmd_unblock),
        (("panic",),               cmd_panic),
        (("mute", "liniste"),      cmd_mute),
        (("unmute",),              cmd_unmute),
    ]
    for names, handler in acting:
        for name in names:
            app.add_handler(CommandHandler(name, _guard(handler)))
    # Inline confirm buttons. The callbacks re-check authorisation themselves,
    # so they are registered without the message-oriented _guard wrapper.
    # Patch buttons first: they carry opaque tokens and must not fall through to
    # the generic handler, which would treat the token as an address.
    app.add_handler(CallbackQueryHandler(on_patch_callback,
                                         pattern=r"^(pap1:|pap2:|pdry:|prej:)"))
    app.add_handler(CallbackQueryHandler(on_callback, pattern=r"^(blk:|unblk:|cancel$)"))
    app.add_handler(CallbackQueryHandler(on_flush_callback, pattern=r"^flush$"))
    return app
