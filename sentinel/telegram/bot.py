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

The command menu comes from the same table the handlers are registered from, is
published at startup to each allowed chat's own scope (never the default one —
see `_publish_commands`), and is read back before anything says it worked. It
was missing entirely until August 2026: twenty-three working commands, an empty
`getMyCommands`, and an operator reporting a command as broken because nothing
in the interface admitted it existed.

Every message this process sends names the installation it came from. That is
done once, in `StampingBot` at the foot of this file, because two Sentinels
sharing one token is a thing that happens and the messages are otherwise
indistinguishable — see `sentinel/telegram/identity.py`.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from telegram import (
    BotCommand,
    BotCommandScopeChat,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ExtBot,
)
from telegram.request import HTTPXRequest

from sentinel import __version__
from sentinel.config import Config, Secrets
from sentinel.db.engine import Database
from sentinel.db.repo import assets as assets_repo
from sentinel.db.repo import blocklist as blocklist_repo
from sentinel.db.repo import capacity as capacity_repo
from sentinel.db.repo import chats as chats_repo
from sentinel.db.repo import health as health_repo
from sentinel.db.repo import incidents as inc_repo
from sentinel.errors import ExecutorRejected, ExecutorUnavailable
from sentinel.logging_setup import get_logger
from sentinel.respond import actions
from sentinel.telegram import views
from sentinel.util import tz
from sentinel.telegram.identity import current_tag, stamp

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

        # `_authorized` returned true, so there is a chat.
        chat = update.effective_chat
        message = update.effective_message
        text = (message.text or message.caption or "") if message else ""

        # `telegram_chats.commands_count` and `.last_command_at` have existed
        # since 0006 and were never written by anything. Two columns that look
        # exactly like a record of the operator's commands, holding 0 and NULL
        # on a host where commands demonstrably arrived — read as evidence
        # during a diagnosis, they sent it down the wrong road for an hour.
        #
        # Written HERE, before the handler runs, and not after it returns: a
        # command that reached a handler and then crashed still arrived, and
        # "did my command get here at all" is the question these columns are
        # looked at to answer. The success line below is the one that says it
        # also worked.
        #
        # Two columns are not an audit trail — they cannot say WHICH command —
        # so the journal line below carries that. What they do hold, and
        # nothing else does, is per-chat usage that survives log rotation.
        db = context.bot_data.get("db")
        if db is not None:
            try:
                await chats_repo.record_command(db, chat.id)
            except Exception as exc:  # noqa: BLE001 - a counter must never eat a command
                # Not fatal, and not silent either: if this starts failing, the
                # columns go stale, and a stale counter read as current is the
                # very defect this code exists to remove.
                log.warning("command not recorded",
                            extra={"chat_id": chat.id,
                                   "detail": f"{type(exc).__name__}: {exc}"})
        # `db` missing is not reported here on purpose: every handler reads it
        # from the same dict and fails loudly one line later, so a second
        # warning would only add noise to an already-loud failure.

        try:
            await handler(update, context)
        except Exception as exc:  # noqa: BLE001 - a broken command must not kill the bot
            # Linia veche — `extra={"detail": str(exc)}` — chiar a funcționat
            # pentru eșecul de CHECK al lui `/mute`: asyncpg pune în mesaj și
            # numele constrângerii, și rândul respins, deci acolo se vedeau și
            # chat_id-ul, și valoarea. Dar asta a fost noroc, nu proiectare — a
            # ținut fiindcă excepția venea din baza de date și purta rândul cu ea.
            #
            # Cazul în care nu ține e chiar celălalt defect din fișierul ăsta:
            # `_fmt_local`, apelat din trei locuri și nedefinit. Tot ce spunea
            # linia veche despre el era `name '_fmt_local' is not defined` — fără
            # chat, fără comandă, și fără să distingă între `/mute 2h` și `/mute`
            # cu o pauză activă. Adaugă deci exact ce lipsea acolo:
            #   * `exc_info` — traceback-ul, adică LINIA care a picat;
            #   * textul comenzii — aici argumentul e cel care declanșează, nu
            #     numele comenzii, iar el nu apare în nicio excepție;
            #   * chat_id și tipul excepției explicit, ca să nu mai depindă de ce
            #     se întâmplă să conțină mesajul.
            # Textul e trunchiat, fiindcă vine de la un client și lungimea lui nu
            # e mărginită de nimic; `RedactingFilter` curăță ce arată a credențial
            # pe drumul spre jurnal.
            log.error(
                "telegram handler failed",
                exc_info=exc,
                extra={
                    "handler": getattr(handler, "__name__", repr(handler)),
                    "chat_id": chat.id if chat else None,
                    "command": text[:200] or None,
                    "detail": f"{type(exc).__name__}: {exc}",
                },
            )
            if update.message:
                await update.message.reply_text("A apărut o eroare la procesarea comenzii.")
        else:
            # Nothing logged a command that WORKED. For a control channel that
            # can block addresses and flush the firewall, "what was asked, by
            # whom, when" existed only for the failures — the successful half
            # left no trace anywhere, in the journal or in the database.
            #
            # One line per accepted command, same fields as the failure line so
            # the two can be read together. Truncated for the same reason, and
            # `RedactingFilter` cleans it on the way out.
            log.info(
                "telegram command",
                extra={
                    "handler": getattr(handler, "__name__", repr(handler)),
                    "chat_id": chat.id,
                    "command": text[:200] or None,
                },
            )
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
    "cidr_requires_ttl": "interval fără expirare configurată",
    "max_active_cidrs": "plafon de intervale active atins",
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


def _kb_from_row(row: Any) -> InlineKeyboardMarkup | None:
    """Tastatura unei notificari generice, din coloana `buttons`.

    Pana acum coloana exista si nu era citita niciodata: coada generica trimitea
    numai text. Un buton scris in tabela si neafisat e mai rau decat lipsa lui —
    producatorul crede ca a oferit o actiune care nu ajunge nicaieri.

    Datele de apel sunt OPACE aici: se trec asa cum au fost scrise, iar
    verificarea de autorizare se face in `_on_callback`, la apasare. O tastatura
    care ar decide singura ce e permis ar fi un al doilea loc in care se scrie
    politica.
    """
    try:
        butoane = json.loads(row["buttons"]) if isinstance(row["buttons"], str) \
            else (row["buttons"] or [])
    except (TypeError, ValueError):
        return None
    randuri = [[InlineKeyboardButton(b["text"], callback_data=b["data"])
                for b in butoane if b.get("text") and b.get("data")]]
    return InlineKeyboardMarkup(randuri) if randuri[0] else None


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


async def cmd_intreaba(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """`/intreaba <întrebare>` — întrebări în limbaj natural despre starea
    serverului, răspunse dintr-un catalog fix de interogări scrise de mână
    (`sentinel/ai/ask.py`). Modelul alege DOAR cheia din catalog și parametrii
    ei, validați în Python contra unor limite absolute; nu scrie și nu compune
    niciun SQL — vezi docstring-ul modulului pentru de ce granița asta contează
    exact aici, unde întrebarea vine dintr-un canal Telegram.

    Read-only prin construcție: fiecare interogare din catalog e un SELECT.
    """
    from sentinel.ai import ask as ask_mod
    from sentinel.config import get_secrets
    from sentinel.db.repo import ask_log as ask_log_repo

    db: Database = context.bot_data["db"]
    cfg: Config = context.bot_data["cfg"]
    chat_id = update.effective_chat.id

    question = " ".join(context.args or []).strip()
    if not question:
        await update.message.reply_text(
            "Folosire: <code>/intreaba &lt;întrebare&gt;</code>\n\nPot răspunde la:\n"
            + _esc(ask_mod.catalog_help_ro()), parse_mode=ParseMode.HTML)
        return

    api_key = get_secrets().get("ANTHROPIC_API_KEY")
    if not api_key:
        await update.message.reply_text(
            "Funcția are nevoie de o cheie API Anthropic, care nu e configurată acum.")
        return
    if not cfg.ai.enabled:
        await update.message.reply_text("Stratul AI e dezactivat în configurație.")
        return

    # Plafon per chat: comanda face DOUĂ apeluri către model, deci apăsată în
    # buclă costă de două ori mai repede decât orice altă comandă din bot.
    # `ask_rate_limit_per_hour` există în config din schema inițială și nu era
    # citit de nimic — vezi 0041_ask_log.sql.
    limit = cfg.ai.ask_rate_limit_per_hour
    used = await ask_log_repo.count_last_hour(db, chat_id)
    if used >= limit:
        await update.message.reply_text(
            f"Ai atins limita de {limit} întrebări pe oră pentru acest chat. "
            "Mai încearcă peste puțin timp.")
        return

    # Scrierea în `ask_log` trece prin `on_attempt`, NU se face aici înainte de
    # apel: `answer_question` mai are propriul ei refuz de buget, iar o comandă
    # refuzată acolo n-a atins niciodată modelul — n-are voie să consume din
    # plafonul orar al chat-ului (`ask_log.py` promite explicit „per attempt
    # that actually reaches the model"). `on_attempt` rulează exact o dată, deci
    # scrierea tot ține fereastra de cursă (verifică-apoi-scrie) cât un
    # round-trip la bază, nu cât toată comanda — la fel ca înainte.
    async def _consuma_plafonul() -> None:
        await ask_log_repo.record(db, chat_id)

    result = await ask_mod.answer_question(db, cfg, api_key, question,
                                           on_attempt=_consuma_plafonul)
    text = _esc(result.text)
    if result.based_on:
        text += f"\n\n<i>Bazat pe: {_esc(result.based_on)}</i>"
    if result.ok and not result.ai_formulated:
        text += "\n<i>(date reale; doar formularea în limbaj natural a lipsit)</i>"
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


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


async def cmd_exposures(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """`/expuneri` — ce ascultă pe toate interfețele, și ce anume e fiecare.

    Nu e o listă de porturi; aia exista deja și a fost citită o dată. Fiecare
    rând spune CE e serviciul și dacă operatorul a decis că e intenționat.
    """
    from sentinel.detect import exposed

    db: Database = context.bot_data["db"]
    rows = await exposed.list_exposures(db)
    if not rows:
        await update.message.reply_text(
            "Niciun serviciu clasificat legat pe toate interfețele.\n"
            "<i>Clasificarea e după port; un serviciu pe un port neobișnuit nu apare.</i>",
            parse_mode=ParseMode.HTML)
        return

    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "⚪"}
    lines = ["<b>Servicii legate pe toate interfețele</b>", ""]
    for r in rows:
        mark = " ✅ <i>intenționat</i>" if r["acknowledged"] else ""
        lines.append(f"{icon.get(r['severity'], '⚪')} <code>{r['key']}</code> — "
                     f"{_esc(r['service'])}{mark}")
    lines += ["", "<code>/stiu tcp/10000</code> marchează o expunere ca intenționată.",
              "<code>/stiu tcp/10000 nu</code> anulează marcajul."]
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_ack_exposure(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """`/stiu <cheie> [nu]` — „știu, e al meu".

    Rolul se verifică aici: a face o alertă critică să tacă permanent e o
    acțiune, nu o citire, chiar dacă nu schimbă nimic pe server.
    """
    from sentinel.detect import exposed

    cfg: Config = context.bot_data["cfg"]
    if not _can_act(cfg, update.effective_chat.id):
        await update.message.reply_text("Doar owner/operator pot marca expuneri.")
        return
    if not context.args:
        await update.message.reply_text(
            "Folosire: <code>/stiu tcp/10000</code> — marchează ca intenționat\n"
            "<code>/stiu tcp/10000 nu</code> — anulează marcajul",
            parse_mode=ParseMode.HTML)
        return

    key = context.args[0]
    on = not (len(context.args) > 1 and context.args[1].lower() in ("nu", "no", "off"))
    db: Database = context.bot_data["db"]
    if await exposed.acknowledge(db, key, on=on):
        await update.message.reply_text(
            f"<code>{_esc(key)}</code> " + ("marcat ca intenționat — nu mai alertează."
                                            if on else
                                            "nu mai e marcat; revine la raportare."),
            parse_mode=ParseMode.HTML)
    else:
        await update.message.reply_text(
            f"Nu am observat <code>{_esc(key)}</code>. Vezi <code>/expuneri</code>.",
            parse_mode=ParseMode.HTML)


async def cmd_incident(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db: Database = context.bot_data["db"]
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Folosire: <code>/incident &lt;id&gt;</code>", parse_mode=ParseMode.HTML)
        return
    inc = await inc_repo.get_incident(db, int(context.args[0]))
    if inc is None:
        await update.message.reply_text("Incident inexistent.")
        return
    cfg: Config = context.bot_data["cfg"]
    dets = await inc_repo.incident_detections(db, inc.id, limit=5)
    text = format_incident(inc)
    if dets:
        det_lines = "\n".join(
            f"• {_esc(tz.fmt(d['ts'], '%H:%M:%S', tz_name=cfg.timezone))} "
            f"{_esc(d['rule_id'])} [{_esc(d['severity'])}]"
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
    if data.startswith("nteu:"):
        # „Nu sunt eu": blochează adresa sesiunii ȘI o închide.
        #
        # Butonul poartă identificatorul SESIUNII, nu adresa. Adresa se citește
        # ACUM din rândul sesiunii — un buton care ar purta-o ar putea fi apăsat
        # peste trei ore, când de pe adresa aia e conectat altcineva.
        session_id = data.split(":", 1)[1]
        db = context.bot_data["db"]
        row = await db.fetchrow(
            "SELECT session_key, host(src_ip) AS ip, username, closed_at "
            "FROM login_sessions WHERE id = $1::bigint",
            int(session_id) if session_id.isdigit() else -1)
        if row is None or not row["ip"]:
            await query.edit_message_text("Sesiunea nu mai există în evidență.")
            return
        try:
            rezultat = await actions.block_and_terminate(
                db, row["ip"], row["session_key"],
                by=f"telegram:{update.effective_chat.id}",
                reason="operator: nu sunt eu")
        except Exception as exc:  # noqa: BLE001
            await query.edit_message_text(f"Nu am putut: {_esc(exc)}")
            return

        linii = []
        if rezultat["allowlisted"]:
            # Se SPUNE ce nu s-a făcut și de ce. Un buton care raportează succes
            # după ce a sărit peste jumătate din ce promitea e mai rău decât unul
            # care eșuează: cine îl apasă pleacă crezând că adresa e blocată.
            linii.append(f"⚠️ <code>{_esc(row['ip'])}</code> e în allowlist — "
                         f"NU am blocat-o. Ar fi însemnat să te închizi singur "
                         f"afară. Dacă chiar vrei: <code>/block "
                         f"{_esc(row['ip'])}</code>")
        else:
            linii.append(f"🚫 Blocat <code>{_esc(row['ip'])}</code>.")
        linii.append("🔒 Sesiune închisă." if rezultat["terminated"]
                     else "⚠️ Sesiunea nu s-a putut închide — poate se "
                          "terminase deja.")
        linii.append("")
        linii.append("Deblocarea readuce accesul, nu și sesiunea.")
        kb = None
        if rezultat["blocked"]:
            kb = InlineKeyboardMarkup([[
                InlineKeyboardButton(f"↩️ Deblochează {row['ip']}",
                                     callback_data=f"unblk:{row['ip']}"),
            ]])
        await query.edit_message_text("\n".join(linii),
                                      parse_mode=ParseMode.HTML, reply_markup=kb)
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


# Referit de două ori mai jos și nedefinit nicăieri: `/mute` fără argumente și
# `/mute <ceva neînțeles>` ridicau amândouă NameError. Comanda de status nu a
# funcționat niciodată, iar singurul mod de a afla era să o folosești exact
# atunci când voiai să verifici dacă ești în liniște.
_MUTE_HELP = (
    "<b>Liniște</b> — pentru acest chat, nu pentru toți.\n\n"
    "<code>/mute 22:00-06:00</code> — în fiecare zi\n"
    "<code>/mute 22:00-06:00; vi,sa 22:00-09:00</code> — plus weekendul\n"
    "<code>/mute 2h</code> — pauză unică, expiră singură\n"
    "<code>/mute off</code> — șterge tot\n\n"
    "<i>Zile: lu ma mi jo vi sa du, sau `weekend`, `lucratoare`. "
    "O fereastră care trece peste miezul nopții aparține serii în care începe — "
    "pentru liniște sâmbătă dimineața, noaptea care contează e a lui vineri.</i>"
)


# Al doilea nume apelat și nedefinit din același fișier, după `_MUTE_HELP`:
# chemat de trei ori mai jos, deci `/mute 2h` și `/mute` fără argumente cu o
# pauză activă ridicau amândouă NameError — adică exact formele pe care textul de
# ajutor le oferă. Ramuri rar atinse: nu se văd la import și nu se văd în
# happy-path-ul unde nu e nicio liniște setată.
def _fmt_local(moment: datetime, tz_name: str | None) -> str:
    """A moment in the chat's own local time, for a reply the operator reads.

    Same shape as everywhere else the bot prints an expiry — `%d.%m %H:%M`, as
    in the blocklist listing. Nothing here is ever more than 24 hours away (an
    ad-hoc mute is capped, and a quiet window ends within the day), so the year
    would be noise.

    Poartă și marcajul de fus — `28.08 06:00 EEST`. Fără el, ora la care se
    ridică liniștea e o afirmație pe care operatorul trebuie s-o ghicească, iar
    între UTC și EEST sunt trei ore: destul cât să creadă că e liniște când nu e.

    Corpul a fost mutat în `sentinel/util/tz.py`, care face aceleași două
    lucruri și pentru restul afișărilor: tratează un `datetime` naiv cu o linie
    de avertisment (baza întoarce `timestamptz`, deci unul naiv înseamnă că
    altceva e stricat, iar `.astimezone()` l-ar citi tăcut în ora procesului) și
    rezolvă `tz_name=None` la fusul gazdei. E aceeași funcție pe care o
    reexportă `quiet.zone` și al cărei nume îl tipărește confirmarea lui
    `/mute`, deci ora afișată și fusul anunțat nu pot să nu fie de acord.
    """
    return tz.fmt(moment, tz.SHORT, tz_name=tz_name)


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
        sched = quiet.parse_schedule(prefs.quiet_hours or cfg.telegram.quiet_hours or "")
        state = quiet.evaluate(now=datetime.now(_tz.utc), schedule=sched,
                               muted_until=prefs.muted_until, tz_name=tz_name)
        lines = [_MUTE_HELP, ""]
        lines.append(f"Program: <b>{_esc(quiet.describe(sched))}</b>")
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
    if (sched := quiet.parse_schedule(arg)) is not None:
        await chats_repo.set_quiet_hours(db, chat_id, str(sched), tz=tz_name)
        log.warning("quiet hours set", extra={"chat_id": chat_id, "schedule": str(sched)})

        # Ce ACOPERĂ fiecare regulă, nu doar ce s-a scris. O fereastră care trece
        # peste miezul nopții aparține zilei în care începe, deci
        # „weekend 22:00-09:00" liniștește diminețile de duminică și luni — nu pe
        # cele de sâmbătă și duminică. Spus aici, corectarea costă o comandă;
        # descoperit singur, costă o dimineață trezită.
        detail = "\n".join(f"• {_esc(quiet.covers(r))}" for r in sched.rules)
        await update.message.reply_text(
            f"🔕 <b>{_esc(str(sched))}</b>\n{detail}\n"
            f"Fus orar: <code>{_esc(str(quiet.zone(tz_name)))}</code>\n\n"
            "<i>Criticele, PANIC, autoverificarea și eșecurile de patch trec "
            "oricum. Restul sosesc la sfârșitul intervalului.</i>",
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

    # Regula însăși stă în `quiet.silent_chats`, nu aici: de când o citește și
    # autoverificarea, o a doua copie ar fi însemnat două răspunsuri la aceeași
    # întrebare, iar cel care se desparte primul e mereu cel netestat.
    return set(quiet.silent_chats(
        now=datetime.now(_tz.utc),
        chat_ids=cfg.telegram.allowed_chat_ids,
        prefs=await chats_repo.all_prefs(db),
        default_schedule=cfg.telegram.quiet_hours,
        default_tz=getattr(cfg.telegram, "timezone", None)))


async def _broadcast(app: Application, cfg: Config, text: str,
                     kb: InlineKeyboardMarkup | None = None, *,
                     quiet_chats: set[int] | None = None,
                     severity: str | None = None, kind: str | None = None) -> int:
    """Send to every allowed chat. Returns how many actually went out.

    A chat inside its quiet window is skipped — unless the message is one that
    is never muted, in which case the window is ignored entirely. See
    `telegram/quiet.py` for what qualifies and why.

    `text` is NOT stamped with the instance name here, and that is deliberate:
    `app.bot` is a `StampingBot`, which does it for every message leaving this
    process, including the ones that never come through this function. Doing it
    here as well would name the instance twice on this path and not at all on
    the others.
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
        "SELECT id, severity, title, body, kind, buttons FROM notifications "
        "WHERE state = 'queued' AND channel = 'telegram' "
        "ORDER BY enqueued_at LIMIT 5")
    from sentinel.telegram.quiet import all_silent, passes_anyway

    all_quiet = all_silent(quiet_chats, cfg.telegram.allowed_chat_ids)

    for row in rows:
        # ȚINUT, nu marcat eșuat. Distincția asta lipsea, iar consecința era că
        # un mesaj amânat de fereastra de liniște se PIERDEA: `_broadcast`
        # întorcea 0, iar rândul primea `failed` și nu se mai încerca niciodată.
        # Calea incidentelor face lucrul corect de mult (`notified_at` rămâne
        # NULL); asta nu-l făcea, deci „se ține până se ridică fereastra" era o
        # afirmație din documentație pe care codul o contrazicea.
        #
        # Rămâne `queued`, deci pleacă la ciclul următor de după ridicarea
        # ferestrei — și nu se atinge `attempts`, fiindcă n-a fost o încercare.
        # Felul CALATORESTE pe rand, de la 0026. Ghicit la livrare — cum era
        # pana acum, cu `"selfcheck"` scris in cod — al doilea producator ar fi
        # fost tacut de fereastra de liniste, iar simptomul ar fi fost liniste:
        # adica nimic de observat.
        kind = row["kind"]
        if all_quiet and not passes_anyway(row["severity"], kind=kind):
            log.info("notification held for quiet hours",
                     extra={"id": row["id"], "severity": row["severity"]})
            continue

        # Ce se ține și ce nu se decide din SEVERITATE și din FEL: vezi nota
        # lungă din `telegram/quiet.py` despre jumătatea care a fost scoasă din
        # scutire, și cea despre `login`, care nu se tace niciodată.
        sent = await _broadcast(app, cfg, row["body"], _kb_from_row(row),
                                quiet_chats=quiet_chats,
                                severity=row["severity"], kind=kind)
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


# --- the command table ------------------------------------------------------
@dataclass(frozen=True)
class Command:
    """One command: the names it answers to, the handler, and the menu text.

    `names[0]` is the canonical name — the ONLY one published to Telegram. The
    rest are aliases: they keep working, they just do not clutter the menu.
    Canonical is not "the English one" and not "the Romanian one"; it is **the
    name the bot itself tells the operator to type** — `/ajutor` in the reply of
    `/status`, `/expuneri` in the reply of `/stiu`, `/incident <id>` at the foot
    of every alert, and the twenty in `views.HELP`. Any other rule would have
    the menu and the bot's own text disagreeing about the name of the same
    thing, which is worse than either choice.

    The description is interface text, so Romanian, and says what the command
    does FOR the operator rather than what it queries.

    Publishing is not optional in this structure: there is no entry without a
    description, and no way to add a command that the menu then does not carry.
    That is the point — the menu was empty on the host for as long as the bot
    has existed, because it was a second list nobody had written.
    """

    names: tuple[str, ...]
    handler: Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[None]]
    description: str

    @property
    def canonical(self) -> str:
        return self.names[0]


# Every command, and the Romanian name for each one. The interface language is
# Romanian, so `/incidente` has to work; the English names stay because they are
# what the documentation and the phone's autocomplete already learned, and
# dropping them would break both.
#
# No diacritics anywhere in a NAME: Telegram accepts [a-z0-9_] and
# `python-telegram-bot` raises ValueError at REGISTRATION — before the bot
# starts. One `ș` in one alias stopped the whole alerting channel, with 1113
# restarts before anyone noticed. Descriptions are free text and may have them.
READ_ONLY = [
    Command(("ajutor", "start", "help"), views.cmd_help,
            "Toate comenzile, pe grupe"),
    Command(("dashboard", "panou"), views.cmd_dashboard,
            "Verdict, cifre, observații, top atacatori"),
    Command(("status",), cmd_status,
            "O linie: incidente deschise și servicii"),
    Command(("incidente", "incidents"), cmd_incidents,
            "Incidentele deschise, cele mai recente"),
    Command(("incident",), cmd_incident,
            "Dosarul unui incident: /incident 42"),
    Command(("vulnerabilitati", "vulns"), views.cmd_vulns,
            "Vulnerabilități deschise, prioritizate"),
    Command(("vuln",), views.cmd_vuln,
            "Detaliul unei vulnerabilități: /vuln 7"),
    Command(("evenimente", "events"), views.cmd_events,
            "Evenimente brute, opțional pentru un IP"),
    Command(("servicii", "services"), cmd_services,
            "Fiecare serviciu: activ, degradat sau picat"),
    Command(("health", "sanatate"), cmd_health,
            "Capacitate: CPU, RAM, disc, conexiuni"),
    Command(("selfcheck", "autoverificare"), views.cmd_selfcheck,
            "Chiar funcționează Sentinel? fiecare componentă"),
    Command(("comportament", "behaviour", "profil"), views.cmd_behaviour,
            "Ce a învățat agentul despre ce e normal aici"),
    Command(("blocklist", "blocate"), views.cmd_blocklist_full,
            "Ce IP-uri sunt blocate acum, și până când"),
    Command(("expuneri", "exposures", "expunere"), cmd_exposures,
            "Ce ascultă pe toate interfețele"),
    Command(("patches", "patch", "patchuri"), cmd_patches,
            "Planuri de patch în așteptare; /patch 3 pentru unul"),
    Command(("intreaba", "ask"), cmd_intreaba,
            "Întreabă în cuvinte proprii: /intreaba câte incidente critice azi?"),
]

# State-changing. Each re-checks the role itself; `_guard` only enforces the
# chat allowlist, which is not the same thing.
ACTING = [
    Command(("rezolva", "resolve"), cmd_resolve,
            "Închide un incident: /rezolva 42 [notă]"),
    Command(("fp", "falspozitiv"), cmd_false_positive,
            "Închide un incident ca fals-pozitiv: /fp 42"),
    Command(("stiu", "ack"), cmd_ack_exposure,
            "Marchează o expunere ca intenționată: /stiu tcp/10000"),
    Command(("block", "blocheaza"), cmd_block,
            "Blochează un IP: /block 203.0.113.7 24h"),
    Command(("unblock", "deblocheaza"), cmd_unblock,
            "Deblochează un IP: /unblock 203.0.113.7"),
    Command(("panic",), cmd_panic,
            "Golește tot blocklist-ul (cere confirmare)"),
    Command(("mute", "liniste"), cmd_mute,
            "Liniște pentru acest chat: /mute 22:00-06:00"),
    Command(("unmute",), cmd_unmute,
            "Gata cu liniștea: alertele revin în acest chat"),
]

COMMANDS = [*READ_ONLY, *ACTING]


def menu_commands() -> list[BotCommand]:
    """The menu Telegram is asked to show, derived from the table above.

    Derived, never written out a second time: a grammar in two places, a
    vocabulary in two places and a key list in two places have each cost this
    repository an outage, and a menu typed by hand next to the handlers would be
    the same defect with a friendlier face.
    """
    return [BotCommand(c.canonical, c.description) for c in COMMANDS]


async def _publish_commands(app: Application, cfg: Config) -> None:
    """Put the menu in front of the operator, and check that it is really there.

    Scoped per chat, not to the default scope. The default scope is what anyone
    who knows the bot's username sees, and this file's posture is that an
    unauthorised chat learns nothing — not even that the bot exists (see the
    module docstring). A menu listing /panic and /block would say a great deal.

    Two calls per chat, on purpose. `setMyCommands` returning True means the
    request was accepted; it is not proof the menu is there, and this repository
    has shipped that confusion in five other shapes (see CLAUDE.md).
    `getMyCommands` for the same scope is the observable fact, and it is a real
    round trip — PTB does not cache it.

    Never raises. The menu is a convenience; the alerting channel is not, and a
    rate limit at startup must not cost the operator the only way this agent can
    speak. Never silent either: an hour went into a symptom that had left no
    trace in the journal.
    """
    commands = menu_commands()
    wanted = {(c.command, c.description) for c in commands}
    chat_ids = list(cfg.telegram.allowed_chat_ids)
    if not chat_ids:
        log.warning("no allowed chat, so no command menu was published")
        return

    published = 0
    for chat_id in chat_ids:
        scope = BotCommandScopeChat(chat_id=chat_id)
        try:
            await app.bot.set_my_commands(commands, scope=scope)
        except Exception as exc:  # noqa: BLE001 - a menu is never worth the channel
            log.warning("command menu not published",
                        extra={"chat_id": chat_id, "commands": len(commands),
                               "detail": f"{type(exc).__name__}: {exc}"})
            continue
        try:
            live = await app.bot.get_my_commands(scope=scope)
        except Exception as exc:  # noqa: BLE001
            # Sent, and unconfirmed. That is a third state, not a success: say
            # so, because "unknown" and "fine" are different things.
            log.warning("command menu sent but not confirmed",
                        extra={"chat_id": chat_id,
                               "detail": f"{type(exc).__name__}: {exc}"})
            continue
        # Equality, not "everything we sent is in there": if Telegram holds a
        # command we no longer have a handler for, the menu offers the operator
        # something that will never answer, and that is worth a line too.
        have = {(c.command, c.description) for c in live}
        if have != wanted:
            log.warning("command menu is not what was sent",
                        extra={"chat_id": chat_id, "live": len(live),
                               "missing": ", ".join(sorted(n for n, _ in wanted - have))[:300],
                               "unexpected": ", ".join(sorted(n for n, _ in have - wanted))[:300]})
            continue
        published += 1

    if published:
        log.info("command menu published",
                 extra={"chats": published, "commands": len(commands)})
    else:
        log.warning("command menu reached no chat", extra={"chats": len(chat_ids)})


# --- who is speaking --------------------------------------------------------
# A sentinel of our own for "the caller passed nothing". PTB has one
# (`telegram._utils.defaultvalue.DEFAULT_NONE`) and it is private; what matters
# here is only the difference between forwarding an argument and not forwarding
# it, so a local object does the job without reaching into the library.
_KEEP: Any = object()


class StampingBot(ExtBot):
    """Puts the instance name on every message this process sends.

    **Why here and not in each formatter.** On 27 August 2026 two Sentinels
    alerted into the same chat for nineteen hours and no message said which
    machine it came from; see `sentinel/telegram/identity.py` for the incident.
    The fix has to hold for messages nobody has written yet, so it sits at the
    transport rather than at the forty places that build text. Every route out
    of this process funnels through exactly two Bot methods:

      * `_broadcast`, `patch_flow.send_plan_for_approval` and every
        `reply_text`/`reply_html` end at `Bot.send_message` — PTB's
        `Message.reply_text` is a call to `self.get_bot().send_message`;
      * every confirmation that replaces its own message — `query.
        edit_message_text` in `on_callback`, `on_flush_callback` and
        `patch_flow` — ends at `Bot.edit_message_text`, through
        `Message.edit_text`.

    That routing is a claim about the library, so it is checked rather than
    assumed: `tests/unit/test_telegram_instance_tag.py` drives a real
    `Message.reply_text` and a real `CallbackQuery.edit_message_text` through
    this class and reads back the text PTB was handed.

    The paths that do NOT come through here are the ones that do not use PTB at
    all — `telegram/direct.py`, used by the self-check when the bot is the thing
    that is down, by the vulnerability announcement and by
    `sentinel telegram --send-test`. Those three stamp their own text, and
    `tests/security/test_telegram_names_its_instance.py` is what refuses to let
    a fourth appear unstamped.

    `parse_mode` decides the markup of the header, not whether there is one: a
    `<i>` in a message sent without `parse_mode` would be four literal
    characters in front of the alert.
    """

    def __init__(self, token: str, *, label: Any = "", **kwargs: Any) -> None:
        super().__init__(token, **kwargs)
        # The label, not the finished tag: the tag is rebuilt per message so
        # that an identity which becomes unreadable is admitted in the next
        # message rather than in the next restart. See the module docstring of
        # `telegram/identity.py`.
        self._instance_label = label

    def _stamp(self, text: str, parse_mode: Any) -> str:
        return stamp(text, current_tag(self._instance_label),
                     html=(parse_mode == ParseMode.HTML))

    async def send_message(self, chat_id: Any, text: str,
                           parse_mode: Any = _KEEP, **kwargs: Any) -> Any:
        stamped = self._stamp(text, None if parse_mode is _KEEP else parse_mode)
        if parse_mode is _KEEP:
            return await super().send_message(chat_id, stamped, **kwargs)
        return await super().send_message(chat_id, stamped, parse_mode, **kwargs)

    async def edit_message_text(self, text: str, chat_id: Any = None,
                                message_id: Any = None,
                                inline_message_id: Any = None,
                                parse_mode: Any = _KEEP, **kwargs: Any) -> Any:
        stamped = self._stamp(text, None if parse_mode is _KEEP else parse_mode)
        if parse_mode is _KEEP:
            return await super().edit_message_text(
                stamped, chat_id, message_id, inline_message_id, **kwargs)
        return await super().edit_message_text(
            stamped, chat_id, message_id, inline_message_id, parse_mode, **kwargs)


def build_application(cfg: Config, secrets: Secrets) -> Application:
    token = secrets.require("TELEGRAM_BOT_TOKEN")
    # `.bot(...)` rather than `.token(...)`: the builder would otherwise
    # construct a plain `ExtBot`, and nothing this process sent would say which
    # installation sent it.
    #
    # The two request objects are NOT decoration and must not be dropped.
    # `.token()` does not just pass the token along — it builds the bot through
    # `ApplicationBuilder._build_ext_bot`, which hands it two `HTTPXRequest`s
    # with connection pools of 256 (everything the bot sends) and 1 (long
    # polling). `ExtBot(token)` on its own takes `HTTPXRequest`'s own default
    # for both, which is 1. Handing the builder a bot without them would have
    # quietly cut the outbound pool from 256 to one connection with a 1-second
    # pool timeout — a change to how the alerting channel behaves under load,
    # shipped as a side effect of adding a line of text to a message.
    #
    # The numbers are PTB's, written here because it does not expose them.
    # `test_the_bot_is_configured_exactly_as_the_builder_would_have` compares
    # this bot against one the builder really made, so a change on their side
    # is a red test rather than a slower host.
    app = Application.builder().bot(StampingBot(
        token, label=cfg.instance_label,
        request=HTTPXRequest(connection_pool_size=256),
        get_updates_request=HTTPXRequest(connection_pool_size=1),
    )).build()

    async def post_init(application: Application) -> None:
        db = Database(cfg)
        await db.connect()
        application.bot_data["db"] = db
        application.bot_data["cfg"] = cfg
        application.bot_data["push_task"] = asyncio.create_task(_push_loop(application, cfg, db))
        # After the push loop is running, deliberately: publishing talks to
        # Telegram and can sit on the library's timeouts, and no menu is worth
        # delaying the first alert of the day.
        await _publish_commands(application, cfg)
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

    for command in COMMANDS:
        for name in command.names:
            app.add_handler(CommandHandler(name, _guard(command.handler)))

    # Inline confirm buttons. The callbacks re-check authorisation themselves,
    # so they are registered without the message-oriented _guard wrapper.
    # Patch buttons first: they carry opaque tokens and must not fall through to
    # the generic handler, which would treat the token as an address.
    app.add_handler(CallbackQueryHandler(on_patch_callback,
                                         pattern=r"^(pap1:|pap2:|pdry:|prej:)"))
    app.add_handler(CallbackQueryHandler(on_callback, pattern=r"^(blk:|unblk:|cancel$)"))
    app.add_handler(CallbackQueryHandler(on_flush_callback, pattern=r"^flush$"))
    return app
