"""The patch approval conversation.

Approving a patch is the most consequential thing this bot can do, so the flow
is built to be hard to do by accident and impossible to do by replay:

  * **Two stages.** The first tap does not apply anything — it issues a second
    token and restates what is about to happen, including the downtime. "Are you
    sure" only works as a gate if the second screen carries information the
    first did not.
  * **The button is not the authority.** callback_data holds an opaque token;
    the authority is the row in `approval_tokens`, single-use and bound to
    (chat, plan, plan_hash).
  * **A regenerated plan kills every button already sent.** The token carries
    the hash, so once the bytes change, an old button matches nothing.
  * **Dry run needs no approval.** Seeing what WOULD happen is not a change, and
    requiring ceremony for it just trains people to skip ceremony.
  * **A PIN, if configured, gates the approval itself.** `require_pin_for_apply`
    is defence in depth for a lost or stolen phone: `approve_plan` is not
    called until the correct PIN is typed back, compared constant-time, with a
    per-chat attempt cap. See `on_pin_reply`.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from sentinel.db.engine import Database
from sentinel.db.repo import approvals, patches
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

RISK_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def _esc(value: Any) -> str:
    import html
    return html.escape(str(value), quote=False)


def format_plan(row: patches.PlanRow) -> str:
    """What the operator reads before deciding. Downtime, blast radius and
    reversibility come first because those are the three things that determine
    whether this is a five-minute job or an outage."""
    plan = row.plan
    target = plan.get("target", {})
    risk = plan.get("risk", {})
    vulns = plan.get("vulnerabilities", [])

    # Linked, not printed. This message is where the decision to patch a
    # production box gets made, and "look it up yourself" is a poor way to ask
    # for that decision. Red Hat first: these are RPM findings, so the question
    # is backport status, which NVD answers wrongly for backported packages.
    from sentinel.intel.links import cve_html

    cves = " · ".join(cve_html(v.get("cve"), rpm=True)
                      for v in vulns[:4] if v.get("cve")) or "—"
    lines = [
        f"{RISK_EMOJI.get(row.risk_level, '⚪')} <b>Plan de patch #{row.id}</b> · "
        f"risc <b>{_esc(row.risk_level or '?')}</b>",
        f"<b>Țintă:</b> {_esc(target.get('asset_name', '?'))} "
        f"({_esc(target.get('stack', '?'))})",
        # Not _esc'd: cve_html escapes its own input and returns markup. Passing
        # it through the escaper again would print the anchor tags as text.
        f"<b>Vulnerabilități:</b> {cves}",
        "",
        f"⏱️ Downtime estimat: <b>{row.estimated_downtime_s or 0}s</b>",
        f"💥 Impact: {_esc(risk.get('blast_radius', '?'))}",
        f"↩️ Reversibil: {'da' if row.reversible else '<b>NU</b>'}",
        f"🔄 Necesită reboot: {'<b>DA</b>' if row.requires_reboot else 'nu'}",
        "",
        f"Pași: {len(plan.get('apply', []))} de aplicat · "
        f"{len(plan.get('backup', []))} de salvat · "
        f"{len(plan.get('rollback', []))} de revenire",
    ]
    return "\n".join(lines)


def format_window_notice(row: patches.PlanRow, reason: str) -> str:
    """Anunț informativ despre un plan generat, FĂRĂ buton de aplicare.

    Funcționalitatea 08, runda 2: `unnotified_plans` ține un plan AI în afara
    canalului de aprobare până când fereastra îl eliberează — corect, dar
    tăcerea completă până atunci confunda „nu poate fi aplicat automat" cu
    „nu trebuie să afli că există". Mesajul ăsta e trimis O SINGURĂ DATĂ, nu
    e reluat dacă motivul se schimbă, exact ca butonul de aprobare din
    `send_plan_for_approval` — și, la fel ca acolo, nu conține nimic care
    autorizează o schimbare pe mașină: `/patch <id>` rămâne singura cale
    către cele două atingeri.
    """
    plan = row.plan
    target = plan.get("target", {})
    vulns = plan.get("vulnerabilities", [])

    from sentinel.intel.links import cve_html

    cves = " · ".join(cve_html(v.get("cve"), rpm=True)
                      for v in vulns[:4] if v.get("cve")) or "—"
    lines = [
        f"📋 <b>Plan de patch #{row.id} generat</b> — {_esc(target.get('asset_name', '?'))}",
        f"<b>Vulnerabilități:</b> {cves}",
        "",
        f"Nu e propus automat pentru aprobare: {_esc(reason)}",
        "",
        f"Poate fi revizuit manual cu <code>/patch {row.id}</code>.",
    ]
    return "\n".join(lines)


async def send_plan_for_approval(bot: Any, db: Database, chat_id: int,
                                 row: patches.PlanRow) -> None:
    """Offer a validated plan. Dry-run needs no token; apply starts stage 1."""
    token = await approvals.issue(
        db, purpose="patch_apply", stage=1, chat_id=chat_id,
        plan_id=row.id, plan_hash=row.plan_hash, created_by="push")
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🧪 Dry-run (nu schimbă nimic)",
                              callback_data=f"pdry:{row.id}")],
        [InlineKeyboardButton("✅ Aplică…", callback_data=f"pap1:{token}"),
         InlineKeyboardButton("❌ Respinge", callback_data=f"prej:{row.id}")],
    ])
    await bot.send_message(chat_id, format_plan(row), parse_mode=ParseMode.HTML,
                           reply_markup=kb)


async def on_stage1(update: Update, context: ContextTypes.DEFAULT_TYPE,
                    token: str) -> None:
    """First tap: nothing is applied. Restate the consequences and issue the
    token that can actually authorise the change."""
    query = update.callback_query
    db: Database = context.bot_data["db"]
    chat_id = update.effective_chat.id

    first = await approvals.consume(db, token, purpose="patch_apply",
                                    chat_id=chat_id, used_by=f"telegram:{chat_id}")
    if first is None:
        await query.edit_message_text(
            "⛔ Butonul a expirat sau a fost deja folosit. Cere planul din nou.")
        return

    row = await patches.get_plan(db, first.plan_id or 0)
    if row is None or row.plan_hash != first.plan_hash:
        await query.edit_message_text(
            "⛔ Planul s-a schimbat de când a fost trimis butonul. "
            "Aprobarea a fost anulată — cere planul din nou.")
        return
    if row.status != "validated":
        await query.edit_message_text(f"⛔ Planul nu mai e valabil (stare: {row.status}).")
        return

    stage2 = await approvals.issue(
        db, purpose="patch_apply", stage=2, chat_id=chat_id,
        plan_id=row.id, plan_hash=row.plan_hash, created_by=f"telegram:{chat_id}",
        ttl_s=300)

    target = row.plan.get("target", {})
    warn = ("\n⚠️ <b>Planul se declară IREVERSIBIL</b> — nu există pași de revenire."
            if not row.reversible else "")
    reboot = ("\n⚠️ <b>Necesită REBOOT</b> — serverul va reporni."
              if row.requires_reboot else "")
    await query.edit_message_text(
        f"<b>Confirmi aplicarea?</b>\n\n"
        f"Vei modifica <b>{_esc(target.get('asset_name', '?'))}</b> pe acest server.\n"
        f"Downtime estimat: <b>{row.estimated_downtime_s or 0} secunde</b>.\n"
        f"Se creează întâi un punct de restaurare verificat.{warn}{reboot}\n\n"
        f"<i>Confirmarea expiră în 5 minute.</i>",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("✅ DA, aplică acum", callback_data=f"pap2:{stage2}"),
            InlineKeyboardButton("❌ Renunț", callback_data="cancel"),
        ]]))


async def on_stage2(update: Update, context: ContextTypes.DEFAULT_TYPE,
                    token: str) -> None:
    """Second tap: approve the exact bytes, then run. Everything before this
    point was reversible by walking away."""
    query = update.callback_query
    db: Database = context.bot_data["db"]
    cfg = context.bot_data["cfg"]
    chat_id = update.effective_chat.id
    by = f"telegram:{chat_id}"

    second = await approvals.consume(db, token, purpose="patch_apply",
                                     chat_id=chat_id, used_by=by)
    if second is None or second.stage != 2:
        await query.edit_message_text("⛔ Confirmarea a expirat sau a fost folosită.")
        return

    # Funcționalitatea 08 — oprirea la primul eșec, recitită AICI, nu la
    # propunere: fereastra a putut elibera acest plan cu zile în urmă, iar
    # butonul de mai sus poate fi atins după ce UN ALT plan din fereastră a
    # eșuat deja la aplicare între timp. Verificarea trebuie să stea pe drumul
    # real spre execuție — dacă ar sta doar la propunere, două planuri
    # eliberate înainte de primul eșec s-ar aplica amândouă oricum, indiferent
    # de ordinea în care omul atinge butoanele. Scoasă DELIBERAT înaintea
    # `approve_plan`: planul rămâne 'validated', nu blocat într-o stare
    # 'approved' pe care niciun buton n-o mai poate mișca.
    plan_for_halt = await patches.get_plan(db, second.plan_id or 0)
    if plan_for_halt is not None and plan_for_halt.proposed_by_window:
        halt = await patches.window_halt(db)
        if halt is not None:
            await query.edit_message_text(
                f"⛔ Fereastra de reparare e oprită: planul #{halt['plan_id']} "
                f"(execuția #{halt['execution_id']}) a ieșit '{halt['status']}'. "
                f"Niciun alt plan propus de fereastră nu se mai aplică automat "
                f"până la o decizie a operatorului.")
            return

    # S2: `require_pin_for_apply` used to be read nowhere — the second tap
    # approved and ran the plan regardless of the setting, which is not
    # "defence in depth", it is a config key that does nothing. The PIN now
    # actually gates `approve_plan`: it is not called until the correct PIN
    # is typed. See `on_pin_reply` for why submitting it needs one more line
    # in `bot.py` that this file cannot add on its own.
    if cfg.telegram.require_pin_for_apply:
        pin = _configured_pin()
        if pin is None:
            await query.edit_message_text(
                "⛔ telegram.require_pin_for_apply este activat, dar "
                "TELEGRAM_APPLY_PIN nu e setat în secrets.env — aplicarea e "
                "refuzată, nu trecută cu vederea.")
            return
        prompt = await query.edit_message_text(
            f"🔒 <b>Răspunde la acest mesaj cu PIN-ul</b> ca să confirmi aplicarea "
            f"— ai {PIN_TTL_S // 60} minute.", parse_mode=ParseMode.HTML)
        # S2 (round 2): the prompt's own message_id is recorded so
        # `on_pin_reply` can require the reply to be a reply TO THIS MESSAGE
        # — see the comment there for why a wired-up text handler cannot
        # simply trust "some text arrived while a PIN is pending".
        _pending_pins[chat_id] = _PendingPin(
            plan_id=second.plan_id or 0, plan_hash=second.plan_hash or "", by=by,
            expires_at=time.monotonic() + PIN_TTL_S,
            prompt_message_id=getattr(prompt, "message_id", None))
        return

    await _approve_and_run(db, cfg, query.edit_message_text,
                           plan_id=second.plan_id or 0,
                           plan_hash=second.plan_hash or "", by=by)


async def _approve_and_run(db: Database, cfg: Any, edit: Any, *,
                           plan_id: int, plan_hash: str, by: str) -> None:
    """Approve the exact bytes, then run. Shared by the plain second-tap path
    and the PIN-success path in `on_pin_reply` — `edit` is whichever of
    `CallbackQuery.edit_message_text` or `Message.edit_text` fits the caller,
    both taking the text as their first positional argument."""
    approved = await patches.approve_plan(db, plan_id, by=by, expected_hash=plan_hash)
    if not approved:
        await edit(
            "⛔ Planul nu a putut fi aprobat — s-a schimbat sau nu mai e în starea "
            "'validated'.")
        return
    # Any other button for this plan dies now, including ones in other chats.
    await approvals.revoke_for_plan(db, plan_id)

    await edit("⏳ Aplic planul… primești rezultatul aici.", parse_mode=ParseMode.HTML)
    log.warning("patch approved from telegram", extra={"plan": plan_id, "by": by})

    from sentinel.patch import runner
    try:
        result = await runner.run_plan(db, cfg, plan_id, mode="apply", triggered_by=by)
    except runner.PatchRefused as exc:
        await edit(f"⛔ Refuzat înainte de execuție: {_esc(exc)}")
        return

    icon = {"succeeded": "✅", "rolled_back": "↩️", "rollback_failed": "🔴",
            "aborted": "🟡", "failed": "🔴"}.get(result.status, "❓")
    body = [f"{icon} <b>Patch {result.status}</b> (execuție #{result.execution_id})"]
    if result.error:
        body.append(f"Motiv: {_esc(result.error)}")
    if result.status == "rollback_failed":
        body.append("\n🔴 <b>ROLLBACK-UL A EȘUAT.</b> Serverul poate fi într-o stare "
                    "intermediară. Restaurează manual: punctul de restaurare are "
                    "<code>restore.sh</code>.")
    ok = sum(1 for s in result.steps if s.ok)
    body.append(f"\nPași: {ok}/{len(result.steps)} reușiți")
    await edit("\n".join(body), parse_mode=ParseMode.HTML)


# ---------------------------------------------------------------------------
# S2 — the PIN itself
# ---------------------------------------------------------------------------
# A pending PIN wait, in-process only, keyed by chat_id. A restart drops it —
# the operator just taps "Aplică…" again. Persisting it would need a schema
# change for a "static PIN, defence in depth if a phone is lost" feature;
# worth revisiting if that trade stops being obviously right, not decided
# here (see docs/PATCHING.md).
PIN_TTL_S = 300              # same window as the stage-2 confirmation itself
PIN_MAX_ATTEMPTS = 3


@dataclass
class _PendingPin:
    plan_id: int
    plan_hash: str
    by: str
    expires_at: float
    # The prompt message's own id — `on_pin_reply` requires the reply to
    # point AT THIS MESSAGE, not just "some text arrived in this chat while
    # a PIN was pending". `None` (a prompt the send call failed to report an
    # id for) never matches a real message_id, which is fail-closed on the
    # same reasoning as `expected is None` a few lines down.
    prompt_message_id: int | None = None
    attempts: int = 0


_pending_pins: dict[int, _PendingPin] = {}


def _configured_pin() -> str | None:
    """The operator's PIN, or `None` if it is not set. A blank secret must
    never be treated as "any reply matches" — `on_pin_reply` refuses outright
    rather than comparing against an empty string."""
    from sentinel.config import get_secrets
    pin = get_secrets().get("TELEGRAM_APPLY_PIN")
    return pin if pin else None


async def on_pin_reply(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Consume a text reply as a PIN attempt, if one is pending for this chat.

    Returns `True` if the message was handled as a PIN attempt (right, wrong,
    or expired) and `False` if there is no pending PIN for this chat, so a
    caller wiring this into a generic text handler knows whether to also try
    treating the message as something else.

    NOT YET WIRED to anything: `bot.py` has no text-message handler today —
    every interaction in this flow is an inline-button callback. This
    function is complete and covered by its own tests, but until one line is
    added to `sentinel/telegram/bot.py:build_application`, next to the
    existing `CallbackQueryHandler(on_patch_callback, ...)` registration —

        from telegram.ext import MessageHandler, filters
        app.add_handler(MessageHandler(
            filters.TEXT & filters.REPLY & ~filters.COMMAND, on_pin_reply))

    — no PIN can ever reach it. `bot.py` belongs to a different writer for
    this change. Until that line exists, turning `require_pin_for_apply` on
    makes stage 2 stop and wait for a PIN that cannot be delivered, which is
    deliberate: failing CLOSED (no apply happens) is the same rule this
    codebase applies to every other check it cannot evaluate — the option
    used to fail OPEN instead (it approved and ran regardless), which is the
    defect this fix closes even before the handler is wired.

    Round 2 adds two checks BEFORE anything is treated as a PIN attempt:

    * **The message must be a reply to the PIN prompt itself.** The filter
      in the (not yet wired) handler above is `filters.TEXT & filters.REPLY`
      — any text reply, to ANY message, while a PIN happens to be pending.
      Without pinning it to the prompt's own `message_id`, an unrelated
      message the operator sends to the same chat during the 5-minute
      window (a reply to something else entirely) would be swallowed as a
      WRONG PIN attempt instead of reaching whatever handler it was actually
      meant for — three of those by accident burns all `PIN_MAX_ATTEMPTS`
      and locks out the real approval. A mismatch here returns `False`,
      the same as "no pending PIN", so the message falls through to
      whatever else the caller's dispatcher would have done with it.
    * **The replier must be who tapped stage 2.** Reconstructed the same
      way `by` is built everywhere else in this file — `telegram:{chat_id}`,
      chat-scoped, matching `_can_act`'s own model in `bot.py` (a private
      chat IS the person; a group's members share one allowlist entry).
      This cannot fail today while `_pending_pins` stays keyed by chat_id —
      the lookup above already guarantees it — but it is the same
      belt-and-suspenders this file already applies to `expected is None`:
      if the keying ever changes, THIS is what still refuses instead of
      silently trusting a dict key that no longer means what it used to.
    """
    chat_id = update.effective_chat.id
    pending = _pending_pins.get(chat_id)
    if pending is None:
        return False

    reply_to = update.message.reply_to_message if update.message else None
    if reply_to is None or reply_to.message_id != pending.prompt_message_id:
        return False

    replier = f"telegram:{chat_id}"
    if replier != pending.by:
        return False

    if time.monotonic() > pending.expires_at:
        del _pending_pins[chat_id]
        await update.message.reply_text("⛔ PIN-ul a expirat. Cere planul din nou.")
        return True

    expected = _configured_pin()
    typed = (update.message.text or "").strip()
    # S2 (round 2): `hmac.compare_digest` raises `TypeError` on a `str`
    # containing anything outside ASCII — a typed PIN like "ă1234" or a
    # configured PIN with a diacritic ("parolă") would crash this handler
    # instead of comparing it. Encoding both sides to bytes first is what
    # every other constant-time comparison in this codebase already does;
    # `compare_digest` itself is constant-time on bytes regardless of what
    # they decode to.
    if expected is None or not hmac.compare_digest(
        typed.encode("utf-8"), expected.encode("utf-8")
    ):
        pending.attempts += 1
        if pending.attempts >= PIN_MAX_ATTEMPTS:
            del _pending_pins[chat_id]
            await update.message.reply_text(
                "⛔ Prea multe încercări greșite. Cere planul din nou.")
        else:
            await update.message.reply_text(
                f"⛔ PIN greșit ({pending.attempts}/{PIN_MAX_ATTEMPTS}).")
        return True

    del _pending_pins[chat_id]
    db: Database = context.bot_data["db"]
    cfg = context.bot_data["cfg"]
    progress = await update.message.reply_text("⏳ Aplic planul… primești rezultatul aici.")
    await _approve_and_run(db, cfg, progress.edit_text, plan_id=pending.plan_id,
                           plan_hash=pending.plan_hash, by=pending.by)
    return True


async def on_dry_run(update: Update, context: ContextTypes.DEFAULT_TYPE,
                     plan_id: int) -> None:
    """A dry run changes nothing, so it needs no token and no second screen.

    The result is a REPLY, never an edit of the plan message. Editing was the
    obvious thing to write and it was wrong: `edit_message_text` replaces the
    inline keyboard too, so running a dry-run deleted the approve button —
    turning the one action meant to build confidence before applying into the
    thing that made applying impossible. The plan message stays untouched with
    its buttons; the result appears underneath it, which is also the order the
    decision was actually made in.
    """
    query = update.callback_query
    db: Database = context.bot_data["db"]
    cfg = context.bot_data["cfg"]

    progress = await query.message.reply_text("🧪 Rulez dry-run…")
    from sentinel.patch import runner
    try:
        result = await runner.run_plan(db, cfg, plan_id, mode="dry_run",
                                       triggered_by=f"telegram:{update.effective_chat.id}")
    except runner.PatchRefused as exc:
        await progress.edit_text(f"⛔ {_esc(exc)}")
        return

    lines = [f"🧪 <b>Dry-run {result.status}</b> (execuție #{result.execution_id})", ""]
    for s in result.steps[:12]:
        lines.append(f"{'✓' if s.ok else '✗'} <code>{_esc(s.phase)}/{_esc(s.step_id)}</code>")
    lines.append("\n<i>Nimic nu a fost modificat.</i>")
    lines.append("Butoanele de aprobare sunt pe mesajul planului, mai sus.")
    await progress.edit_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def on_reject(update: Update, context: ContextTypes.DEFAULT_TYPE,
                    plan_id: int) -> None:
    query = update.callback_query
    db: Database = context.bot_data["db"]
    by = f"telegram:{update.effective_chat.id}"
    await patches.reject_plan(db, plan_id, by=by, reason="respins din Telegram")
    await approvals.revoke_for_plan(db, plan_id)
    await query.edit_message_text(f"❌ Planul #{plan_id} a fost respins.")
