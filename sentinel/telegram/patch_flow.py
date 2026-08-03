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
"""

from __future__ import annotations

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

    cves = ", ".join(str(v.get("cve")) for v in vulns[:4] if v.get("cve")) or "—"
    lines = [
        f"{RISK_EMOJI.get(row.risk_level, '⚪')} <b>Plan de patch #{row.id}</b> · "
        f"risc <b>{_esc(row.risk_level or '?')}</b>",
        f"<b>Țintă:</b> {_esc(target.get('asset_name', '?'))} "
        f"({_esc(target.get('stack', '?'))})",
        f"<b>Vulnerabilități:</b> {_esc(cves)}",
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

    approved = await patches.approve_plan(db, second.plan_id or 0, by=by,
                                          expected_hash=second.plan_hash or "")
    if not approved:
        await query.edit_message_text(
            "⛔ Planul nu a putut fi aprobat — s-a schimbat sau nu mai e în starea "
            "'validated'.")
        return
    # Any other button for this plan dies now, including ones in other chats.
    await approvals.revoke_for_plan(db, second.plan_id or 0)

    await query.edit_message_text("⏳ Aplic planul… primești rezultatul aici.",
                                  parse_mode=ParseMode.HTML)
    log.warning("patch approved from telegram",
                extra={"plan": second.plan_id, "chat": chat_id})

    from sentinel.patch import runner
    try:
        result = await runner.run_plan(db, cfg, second.plan_id or 0,
                                       mode="apply", triggered_by=by)
    except runner.PatchRefused as exc:
        await query.edit_message_text(f"⛔ Refuzat înainte de execuție: {_esc(exc)}")
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
    await query.edit_message_text("\n".join(body), parse_mode=ParseMode.HTML)


async def on_dry_run(update: Update, context: ContextTypes.DEFAULT_TYPE,
                     plan_id: int) -> None:
    """A dry run changes nothing, so it needs no token and no second screen."""
    query = update.callback_query
    db: Database = context.bot_data["db"]
    cfg = context.bot_data["cfg"]

    await query.edit_message_text("🧪 Rulez dry-run…")
    from sentinel.patch import runner
    try:
        result = await runner.run_plan(db, cfg, plan_id, mode="dry_run",
                                       triggered_by=f"telegram:{update.effective_chat.id}")
    except runner.PatchRefused as exc:
        await query.edit_message_text(f"⛔ {_esc(exc)}")
        return

    lines = [f"🧪 <b>Dry-run {result.status}</b> (execuție #{result.execution_id})", ""]
    for s in result.steps[:12]:
        lines.append(f"{'✓' if s.ok else '✗'} <code>{_esc(s.phase)}/{_esc(s.step_id)}</code>")
    lines.append("\n<i>Nimic nu a fost modificat.</i>")
    await query.edit_message_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def on_reject(update: Update, context: ContextTypes.DEFAULT_TYPE,
                    plan_id: int) -> None:
    query = update.callback_query
    db: Database = context.bot_data["db"]
    by = f"telegram:{update.effective_chat.id}"
    await patches.reject_plan(db, plan_id, by=by, reason="respins din Telegram")
    await approvals.revoke_for_plan(db, plan_id)
    await query.edit_message_text(f"❌ Planul #{plan_id} a fost respins.")
