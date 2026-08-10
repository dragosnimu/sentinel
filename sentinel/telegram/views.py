"""The read-only half of the dashboard, on a phone.

Every command here answers a question the web UI already answers, using the same
aggregate and repository functions the routers use. Nothing in this file writes
anything, runs anything, or reaches the executor — which is why none of it needs
a role check beyond the chat allowlist.

Three things a chat message is not, and that shape everything below:

  * **It is not a page.** Telegram caps a message at 4096 characters and there
    is no scrollbar. Every list is bounded, and when something is cut the
    message says so rather than ending mid-sentence.
  * **It is not a table.** Columns do not survive a narrow screen. Each row is
    one line, most important value first.
  * **It is not trusted output.** Paths, user agents, usernames and IDS
    signature names are written by whoever is attacking the host, and these
    messages are `parse_mode=HTML`. Everything from the database is escaped.
"""

from __future__ import annotations

import html
from typing import Any

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from sentinel.analytics import aggregate, insights as insights_mod
from sentinel.db.engine import Database
from sentinel.db.repo import blocklist as blocklist_repo
from sentinel.db.repo import events as events_repo
from sentinel.db.repo import findings as findings_repo
from sentinel.intel.links import cve_html, cve_links
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Telegram's hard limit is 4096. Stopping short leaves room for the "cut" note
# and for the closing hint line, which are the two things worth keeping when a
# message is too long.
MAX_MESSAGE = 3600

_SEV_EMOJI = {"info": "⚪", "low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}
_LEVEL_EMOJI = {"critical": "🔴", "warning": "🟡", "good": "🟢", "info": "⚪"}


def esc(value: Any) -> str:
    return html.escape(str(value), quote=False) if value is not None else "—"


def clamp(lines: list[str], *, tail: str = "") -> str:
    """Join lines, stopping before the message limit and saying it was cut.

    Truncating in the middle of a list without a word about it is how an
    operator concludes there were four attackers when there were forty.
    """
    out: list[str] = []
    used = len(tail)
    for line in lines:
        if used + len(line) + 1 > MAX_MESSAGE:
            out.append(f"\n<i>…listă scurtată ({len(lines) - len(out)} rânduri "
                       f"în plus). Vezi panoul web pentru tot.</i>")
            break
        out.append(line)
        used += len(line) + 1
    if tail:
        out.append(tail)
    return "\n".join(out)


async def _reply(update: Update, text: str) -> None:
    await update.effective_message.reply_text(
        text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


# ---------------------------------------------------------------------------
# /dashboard
# ---------------------------------------------------------------------------
async def cmd_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """The whole front page, in the order the page itself uses.

    Verdict first. Someone who opens this at 3 a.m. should be able to stop
    reading after line one if the answer is "nothing is happening".
    """
    db: Database = context.bot_data["db"]

    found = await insights_mod.collect(db)
    posture = await insights_mod.posture(db, found)
    kpi = await aggregate.kpis(db)
    deltas = await aggregate.deltas(db)
    health = await aggregate.service_health(db)

    lines = [
        f"{_LEVEL_EMOJI.get(posture['level'], '⚪')} <b>{esc(posture['verdict'])}</b>",
        f"<i>{posture['atacatori']} atacatori · {posture['evenimente']} evenimente ostile / 24h</i>",
        "",
        "<b>Cifre (24h)</b>",
        f"Evenimente: {kpi['evenimente_24h']:,} · ostile: {kpi['ostile_24h']:,}"
        f"{_delta(deltas, 'ostile')}",
        f"Atacatori unici: {kpi['atacatori_24h']:,}{_delta(deltas, 'atacatori')}",
        f"Incidente deschise: <b>{kpi['incidente_deschise']}</b> "
        f"(grave: {kpi['incidente_grave']})",
        f"Vulnerabilități: {kpi['vuln_deschise']} deschise · {kpi['vuln_kev']} KEV",
        f"IP-uri blocate: {kpi['blocate']}",
        f"Servicii: 🟢 {health.get('up', 0)} · 🔴 {health.get('down', 0)} · "
        f"⚪ {health.get('necunoscut', 0)}",
    ]

    # Only what the page would colour. A phone screen has no room for the
    # "everything is fine" cards, and reading them trains you to skim.
    notable = [i for i in found if i.level in ("critical", "warning")]
    if notable:
        lines += ["", f"<b>Observații ({len(notable)})</b>"]
        for ins in notable[:5]:
            lines.append(f"{_LEVEL_EMOJI.get(ins.level, '⚪')} <b>{esc(ins.title)}</b>")
            lines.append(f"   {esc(ins.detail)}")
            if ins.action:
                lines.append(f"   → <i>{esc(ins.action)}</i>")
        if len(notable) > 5:
            lines.append(f"<i>…și încă {len(notable) - 5}.</i>")
    else:
        lines += ["", "🟢 <b>Nicio observație de semnalat.</b>"]

    attackers = await aggregate.top_attackers(db, limit=5)
    if attackers:
        lines += ["", "<b>Top atacatori (24h)</b>"]
        for a in attackers:
            flag = f" {esc(a['tara'])}" if a.get("tara") else ""
            mark = " 🚫" if a.get("blocat") else ""
            lines.append(f"<code>{esc(a['ip'])}</code>{flag} — {a['ev']} ev "
                         f"({esc(a['care'])}){mark}")

    countries = await aggregate.by_country(db, limit=4)
    if countries:
        lines += ["", "<b>Origine</b> " + " · ".join(
            f"{esc(c['tara'])} {c['ev']}" for c in countries)]

    await _reply(update, clamp(lines, tail="\n/incidente /vulnerabilitati /evenimente /blocklist"))


def _delta(deltas: dict, key: str) -> str:
    d = deltas.get(key) or {}
    return f" ({esc(d['text'])})" if d.get("text") else ""


# ---------------------------------------------------------------------------
# /vulns
# ---------------------------------------------------------------------------
async def cmd_vulns(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Open findings, most urgent first, with a filter argument.

    Ordered by the prioritisation score rather than by CVSS: a critical CVE in
    something not exposed matters less than a medium one being exploited in the
    wild right now, and the score is what already encodes that.
    """
    db: Database = context.bot_data["db"]
    arg = (context.args[0].lower() if context.args else "")

    counts = await findings_repo.open_counts(db)
    rows = await findings_repo.list_open(db, limit=200)

    if arg in ("kev", "exploatate"):
        rows = [r for r in rows if r.get("kev")]
        title = "Vulnerabilități exploatate activ (KEV)"
    elif arg in ("critical", "critice", "high", "mari"):
        wanted = {"critical", "high"} if arg in ("high", "mari") else {"critical"}
        rows = [r for r in rows if r["severity"] in wanted]
        title = f"Vulnerabilități {esc(arg)}"
    else:
        title = "Vulnerabilități deschise"

    if not rows:
        await _reply(update, f"✅ <b>{title}</b>: niciuna.\n"
                             f"<i>Scanarea rulează nocturn; /vuln &lt;id&gt; pentru detaliu.</i>")
        return

    head = " · ".join(
        f"{_SEV_EMOJI[s]}{counts[s]}" for s in ("critical", "high", "medium", "low")
        if counts.get(s)) or "—"
    lines = [f"🛠️ <b>{title}</b> — {len(rows)} afișate",
             f"{head}" + (f" · 🔥 {counts['kev']} KEV" if counts.get("kev") else ""), ""]

    for r in rows[:20]:
        kev = " 🔥" if r.get("kev") else ""
        ref = cve_html(r.get("cve"), rpm=(r.get("scanner") == "dnf"), kev=bool(r.get("kev")))
        lines.append(
            f"{_SEV_EMOJI.get(r['severity'], '⚪')} <b>#{r['id']}</b> {ref}{kev}")
        lines.append(f"   <code>{esc(r.get('package') or r.get('location') or '?')}</code>"
                     f" → {esc(r.get('fixed_version') or 'fără fix cunoscut')}"
                     f" · prio {r.get('priority', 0)}")
    if len(rows) > 20:
        lines.append(f"\n<i>…și încă {len(rows) - 20}.</i>")

    await _reply(update, clamp(lines, tail="\n/vuln &lt;id&gt; · /patch &lt;id&gt; pentru un plan"))


async def cmd_vuln(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    db: Database = context.bot_data["db"]
    if not context.args or not context.args[0].isdigit():
        await _reply(update, "Folosire: <code>/vuln &lt;id&gt;</code> — id-ul din /vulnerabilitati")
        return

    fid = int(context.args[0])
    rows = await findings_repo.list_open(db, limit=1000)
    row = next((r for r in rows if r["id"] == fid), None)
    if row is None:
        await _reply(update, "Vulnerabilitate inexistentă sau deja rezolvată.")
        return

    rpm = row.get("scanner") == "dnf"
    lines = [
        f"{_SEV_EMOJI.get(row['severity'], '⚪')} <b>Vulnerabilitate #{row['id']}</b>"
        + (" · 🔥 <b>exploatată activ</b>" if row.get("kev") else ""),
        f"<b>{esc(row.get('title'))}</b>",
        "",
        f"Pachet: <code>{esc(row.get('package') or '—')}</code>",
        f"Instalat: <code>{esc(row.get('installed_version') or '—')}</code>",
        f"Repară: <code>{esc(row.get('fixed_version') or 'necunoscut')}</code>",
        f"Severitate: {esc(row['severity'])}"
        + (f" · CVSS {row['cvss']}" if row.get("cvss") else "")
        + (f" · EPSS {row['epss']:.0%}" if row.get("epss") else ""),
        f"Prioritate: <b>{row.get('priority', 0)}</b> · scaner: {esc(row.get('scanner'))}",
    ]
    if row.get("asset_name"):
        lines.append(f"Asset: {esc(row['asset_name'])}")
    if links := cve_links(row.get("cve"), rpm=rpm, kev=bool(row.get("kev"))):
        lines += ["", "<b>Detalii:</b> " + " · ".join(
            f'<a href="{url}">{esc(name)}</a>' for name, url in links)]

    if row.get("fixed_version"):
        lines.append(f"\nPlan de remediere: <code>/patch {row['id']}</code>")
    else:
        lines.append("\n<i>Fără versiune care repară — nu se poate genera un plan.</i>")

    await _reply(update, clamp(lines))


# ---------------------------------------------------------------------------
# /events
# ---------------------------------------------------------------------------
async def cmd_events(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Raw events: a summary, then the most recent few.

    `/events <ip>` narrows to one address, which is the question actually asked
    when someone looks at this — "what did THIS one do?" rather than "what
    happened".
    """
    db: Database = context.bot_data["db"]
    arg = context.args[0] if context.args else ""
    src_ip = arg if _looks_like_ip(arg) else None
    minutes = 60

    summary = await events_repo.summary(db, since_minutes=minutes)
    rows = await events_repo.recent(db, limit=15, src_ip=src_ip,
                                    since_minutes=None if src_ip else minutes)

    if src_ip:
        lines = [f"📡 <b>Evenimente de la <code>{esc(src_ip)}</code></b>"]
    else:
        by_source = " · ".join(f"{esc(s['source'])} {s['n']}"
                               for s in summary.get("by_source", [])[:6]) or "—"
        lines = [
            f"📡 <b>Evenimente (ultima oră)</b> — {summary.get('total', 0):,}",
            by_source,
        ]
        top = summary.get("top_ips") or []
        if top:
            lines += ["", "<b>Cele mai active surse</b>"]
            for t in top[:5]:
                fails = f" · {t['auth_fails']} eșecuri auth" if t.get("auth_fails") else ""
                lines.append(f"<code>{esc(t['ip'])}</code> — {t['n']}{fails}")

    if not rows:
        lines.append("\n<i>Niciun eveniment în fereastra asta.</i>")
        await _reply(update, clamp(lines))
        return

    lines += ["", f"<b>Ultimele {len(rows)}</b>"]
    for e in rows:
        lines.append(_format_event(e, with_ip=src_ip is None))

    tail = ("\n<i>/evenimente &lt;ip&gt; pentru o singură sursă</i>"
            if not src_ip else f"\n<code>/block {esc(src_ip)}</code> pentru a bloca")
    await _reply(update, clamp(lines, tail=tail))


def _format_event(e: dict, *, with_ip: bool) -> str:
    """One event, one line. Every field here is attacker-influenced."""
    when = e["ts"].strftime("%H:%M:%S")
    who = f" <code>{esc(e['src_ip'])}</code>" if with_ip and e.get("src_ip") else ""
    what = esc(e.get("action"))
    detail = ""
    if e.get("http_path"):
        method = esc(e.get("http_method") or "")
        # Truncated before escaping would cut an entity in half and produce
        # broken markup; truncate the raw value, then escape.
        path = str(e["http_path"])[:60]
        detail = f" {method} <code>{esc(path)}</code>"
        if e.get("http_status"):
            detail += f" {e['http_status']}"
    elif e.get("username"):
        detail = f" user=<code>{esc(e['username'])}</code>"
    elif e.get("dst_port"):
        detail = f" :{esc(e['dst_port'])}"
    return f"<code>{when}</code> {esc(e.get('source'))}/{what}{who}{detail}"


def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# /help
# ---------------------------------------------------------------------------
HELP = """🛡️ <b>Sentinel — comenzi</b>

<b>Privire de ansamblu</b>
/dashboard — verdict, cifre, observații, top atacatori
/selfcheck — chiar funcționează Sentinel? fiecare componentă
/status — o linie: incidente și servicii
/health — starea Sentinel însuși

<b>Incidente</b>
/incidente [n] — ultimele incidente
/incident &lt;id&gt; — dosarul complet
/rezolva &lt;id&gt; · /fp &lt;id&gt; — închide, sau marchează fals-pozitiv

<b>Vulnerabilități</b>
/vulnerabilitati [kev|critice|mari] — findings deschise, prioritizate
/vuln &lt;id&gt; — detaliu, cu legături către NVD și Red Hat

<b>Patch-uri</b>
/patches — planuri în așteptare
/patch &lt;id&gt; — planul, cu butoane de aprobare

<b>Trafic și servicii</b>
/evenimente [ip] — evenimente brute
/servicii — fiecare serviciu, up/down și uptime

<b>Răspuns</b>
/block &lt;ip&gt; [ttl] [motiv] · /unblock &lt;ip&gt;
/blocklist — ce e blocat acum
/panic — golește tot blocklist-ul (dublă confirmare)

<b>Notificări</b>
/mute 22:00-06:00 · /mute 2h · /unmute
<i>Criticele, PANIC și eșecurile de patch trec oricum.</i>"""


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _reply(update, HELP)


# ---------------------------------------------------------------------------
# /blocklist detail — the web page shows hit counts; the old command did not
# ---------------------------------------------------------------------------
async def cmd_blocklist_full(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Everything currently blocked, plus what nftables actually holds.

    The two numbers are printed side by side on purpose. They should agree; when
    they do not, the database and the kernel disagree about who is blocked, and
    that is worth seeing rather than averaging away.
    """
    from sentinel.respond import actions

    db: Database = context.bot_data["db"]
    blocks = await blocklist_repo.list_active(db, limit=60)
    live = await actions.live_count()

    if not blocks:
        await _reply(update, f"🚫 <b>Blocklist gol.</b>\n"
                             f"nftables: {live if live >= 0 else '?'} elemente")
        return

    lines = [f"🚫 <b>Blocklist</b> — {len(blocks)} în bază · "
             f"{live if live >= 0 else '?'} în nftables", ""]
    for b in blocks:
        exp = b.expires_at.strftime("%d.%m %H:%M") if b.expires_at else "permanent"
        lines.append(f"<code>{esc(b.ip)}</code> · până la {exp}")
        lines.append(f"   {esc(b.reason or '—')} · {esc(b.created_by)}")

    await _reply(update, clamp(lines, tail="\n<code>/unblock &lt;ip&gt;</code>"))


# ---------------------------------------------------------------------------
# /selfcheck
# ---------------------------------------------------------------------------
async def cmd_selfcheck(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Every self-check, as of the last run — and how long ago that was.

    Reads the recorded state rather than re-running: the checks touch systemd,
    nftables and the executor, and letting a chat message trigger all of that on
    demand is a way to turn a curious operator into load. The timer runs every
    five minutes, so the answer is never stale enough to matter.

    **One source.** The verdict, the count and every line below come from
    `selfcheck_state`; `selfcheck_runs` supplies only the timestamp and the
    duration — it dates the answer, it does not give it. This screen used to
    take "33 verificări" from the runs table and the red line from the state
    table, and the two disagreed for 26 hours: the state table still held a
    finding that no run had produced since the previous morning. The runner now
    reconciles that table after every complete run, so counting the rows shown
    here is the same number the run produced, by construction rather than by
    coincidence.

    A row that survived an INCOMPLETE run is marked `stale` and shown apart. Its
    age is the age of the FINDING, said in those words — an old row presented
    with a bare "· de 27h 54m" next to a headline about a current outage reads
    as the length of the outage, and it is not.
    """
    db: Database = context.bot_data["db"]

    # Two runs, for one reason: to notice that the number of checks dropped.
    # A conditional key can stop being emitted because a source fell out of the
    # collector's 30-day window, and if that key was `ok` nothing announces it —
    # the panel just quietly counts one fewer check than yesterday. That is
    # silent loss of coverage, and a panel that counts something different from
    # one day to the next has to say so.
    runs = await db.fetch(
        "SELECT started_at, worst_status, checks_run, checks_bad, duration_ms "
        "FROM selfcheck_runs ORDER BY started_at DESC LIMIT 2")
    if not runs:
        await _reply(update, "Autoverificarea nu a rulat încă.\n"
                             "<code>systemctl start sentinel-selfcheck</code>")
        return
    run = runs[0]

    rows = await db.fetch(
        "SELECT key, status, title, detail, since, stale FROM selfcheck_state "
        "ORDER BY CASE status WHEN 'down' THEN 0 WHEN 'degraded' THEN 1 "
        "WHEN 'unknown' THEN 2 ELSE 3 END, key")
    if not rows:
        # A run without a single recorded check is not "everything is fine".
        await _reply(update, "⚪ <b>Nu știu dacă Sentinel funcționează</b>\n"
                             "Ultima rulare nu a lăsat nicio verificare în stare.\n"
                             "<code>journalctl -u sentinel-selfcheck -n 50</code>")
        return

    emoji = {"down": "🔴", "degraded": "🟡", "ok": "🟢", "unknown": "⚪"}
    age_min = int((_now() - run["started_at"]).total_seconds() // 60)

    current = [r for r in rows if not r["stale"]]
    stale = [r for r in rows if r["stale"]]
    bad = [r for r in current if r["status"] in ("down", "degraded")]
    unsure = [r for r in current if r["status"] == "unknown"]
    ok_rows = [r for r in current if r["status"] == "ok"]

    # A finding kept from an incomplete run still counts against the verdict:
    # the last thing known about it was that it was broken, and not having
    # re-checked is not evidence to the contrary.
    verdict_rows = bad + [r for r in stale if r["status"] in ("down", "degraded")]
    if any(r["status"] == "down" for r in verdict_rows):
        head = "🔴 <b>Sentinel nu funcționează complet</b>"
    elif verdict_rows:
        head = "🟡 <b>Sentinel funcționează degradat</b>"
    elif unsure or stale:
        head = "⚪ <b>Sentinel pare în regulă, dar nu tot s-a putut verifica</b>"
    else:
        head = "🟢 <b>Totul funcționează</b>"

    count = f"<i>{len(current)} verificări · ultima rulare acum {age_min} min " \
            f"· {run['duration_ms']} ms"
    if stale:
        count += f" · {len(stale)} neevaluate"
    lines = [head, count + "</i>"]

    previous_count = int(runs[1]["checks_run"]) if len(runs) > 1 else len(current)
    if len(current) < previous_count:
        lines.append(f"<i>⚪ cu {previous_count - len(current)} verificări mai puțin "
                     f"decât la rularea anterioară ({previous_count} → {len(current)}) "
                     f"— o constatare s-a retras sau o sursă a ieșit din acoperire</i>")

    # `unsure` is listed with the faults, not folded into "În regulă": a check
    # that could not look is the state this whole package exists to keep
    # distinct from a check that looked and was satisfied. It used to appear in
    # neither list and so was invisible.
    if bad or unsure:
        lines.append("")
    for r in bad + unsure:
        lines.append(f"{emoji[r['status']]} <b>{esc(r['title'])}</b> · de {_since(r)}")
        if r["detail"]:
            lines.append(f"   {esc(r['detail'])}")

    if stale:
        lines += ["", f"<b>Neevaluate la ultima rulare ({len(stale)})</b>",
                  "<i>o rulare întreruptă nu le-a reevaluat; mai jos e ultima "
                  "constatare, nu starea de acum</i>"]
        for r in stale:
            lines.append(f"{emoji[r['status']]} {esc(r['title'])} "
                         f"· constatare veche de {_since(r)}")

    if ok_rows:
        lines += ["", f"<b>În regulă ({len(ok_rows)})</b>"]
        lines.append(" · ".join(esc(r["title"]) for r in ok_rows[:14]))
        if len(ok_rows) > 14:
            lines.append(f"<i>…și încă {len(ok_rows) - 14}.</i>")

    await _reply(update, clamp(lines))


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _since(row) -> str:
    """How long this row has held its current status."""
    minutes = int((_now() - row["since"]).total_seconds() // 60)
    return f"{minutes // 60}h {minutes % 60}m" if minutes >= 60 else f"{minutes}m"


async def cmd_behaviour(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Ce a învățat agentul despre comportamentul normal al serverului.

    Există fiindcă „învață câteva zile" e o promisiune pe care operatorul are
    dreptul să o verifice. Fără comanda asta, perioada de încălzire e o cutie
    neagră: nu se poate deosebi „încă învață" de „nu funcționează", iar
    diferența dintre ele contează exact cât întreaga funcționalitate.
    """
    from sentinel.predict import behaviour as bh

    db: Database = context.bot_data["db"]
    rows = await bh.status(db)

    warm = [r for r in rows if r["warm"]]
    lines = [f"<b>Profil de comportament</b> · {len(warm)}/{len(rows)} dimensiuni active", ""]

    for r in rows:
        if r["warm"]:
            lines.append(
                f"✅ <b>{esc(r['label'])}</b>\n"
                f"    {r['distinct_keys']} valori cunoscute · "
                f"{r['observations']:,} observații · {r['days']:.0f} zile")
        else:
            lines.append(
                f"⏳ <b>{esc(r['label'])}</b>\n"
                f"    învață · {r['distinct_keys']} valori · "
                f"{r['observations']:,} observații · mai are {esc(r['needs'] or '')}")

    if not warm:
        lines += ["", "<i>Cât timp o dimensiune învață, nu alertează deloc. "
                  "Altfel prima zi ar produce o alertă pentru fiecare utilizator, "
                  "fiecare rețea și fiecare binar de pe server.</i>"]
    else:
        recent = await db.fetch(
            "SELECT dimension, key, first_seen FROM behaviour_profiles "
            "WHERE first_seen > now() - interval '7 days' "
            "ORDER BY first_seen DESC LIMIT 8")
        if recent:
            lines += ["", "<b>Valori noi în ultimele 7 zile</b>"]
            for r in recent:
                lines.append(f"  <code>{esc(r['key'])}</code> · "
                             f"{esc(r['dimension'])} · "
                             f"{r['first_seen'].strftime('%d.%m %H:%M')}")

    await update.effective_message.reply_html(clamp("\n".join(lines)))
