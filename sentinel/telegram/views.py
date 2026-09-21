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
from dataclasses import dataclass
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
from sentinel.scan.subject import (KIND_APP, KIND_CONTAINER, KIND_LABELS, KIND_OS,
                                   KIND_UNKNOWN, categories, describe)
from sentinel.util import tz
from sentinel.util.ids import parse_id

log = get_logger(__name__)

# Telegram's hard limit is 4096. Stopping short leaves room for the "cut" note
# and for the closing hint line, which are the two things worth keeping when a
# message is too long.
#
# That headroom now has a third consumer, and it is worth the arithmetic:
# `telegram/identity.py` puts one line naming the instance in front of every
# message on its way out. That line is a 64-character label at most
# (`MAX_LABEL`), an 8-character id, the prefix and the italics — 93 characters
# with the newline, or 349 in the absurd case where every character of the
# label is an `&` and escapes to five. Even then 3600 + 349 is under 4096, so
# nothing clamped here can be pushed over the limit by it and `stamp` never has
# to trim a message this function produced.
#
# Unitatea e **codul UTF-16**, nu caracterul Python, fiindcă aia numără
# Telegram. Un emoji din planurile suplimentare (U+1F600 și mai sus) e un
# singur `len()` și DOUĂ unități pe fir. Măsurat pe o listă construită din
# etichete cu emoji: `len` 3350, unități UTF-16 4914 — peste 4096, deci
# mesajul e refuzat întreg și operatorul primește eroarea generică a lui
# `_guard` în locul răspunsului. Nicio coloană de pe gazdă nu are azi caractere
# ne-ASCII (verificat pe `package`, `location`, `cve`), dar toate trei sunt
# scrise de scanare peste ce găsește pe disc, iar un nume de director sub un
# web root îl alege cine încarcă fișiere acolo.
MAX_MESSAGE = 3600

_SEV_EMOJI = {"info": "⚪", "low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}
_LEVEL_EMOJI = {"critical": "🔴", "warning": "🟡", "good": "🟢", "info": "⚪"}


def esc(value: Any) -> str:
    return html.escape(str(value), quote=False) if value is not None else "—"


def w16(text: str) -> int:
    """Cât ocupă textul în unități UTF-16 — felul în care numără Telegram.

    `len()` numără caractere Python. Pentru orice din planurile suplimentare
    (emoji, alfabete rare) cele două diferă cu factor doi, iar diferența cade
    exact pe partea greșită: bugetul pare respectat și mesajul e refuzat.
    """
    return len(text.encode("utf-16-le")) // 2


def clamp(lines: list[str], *, tail: str = "") -> str:
    """Join lines, stopping before the message limit and saying it was cut.

    Truncating in the middle of a list without a word about it is how an
    operator concludes there were four attackers when there were forty.

    Socoteala e în unități UTF-16 (vezi `MAX_MESSAGE`): numărate în caractere
    Python, un mesaj plin de emoji trece de plafon fără ca nimic de aici să
    observe, iar Telegram refuză tot mesajul, nu doar coada lui.
    """
    out: list[str] = []
    used = w16(tail)
    for line in lines:
        if used + w16(line) + 1 > MAX_MESSAGE:
            out.append(f"\n<i>…listă scurtată ({len(lines) - len(out)} rânduri "
                       f"în plus). Vezi panoul web pentru tot.</i>")
            break
        out.append(line)
        used += w16(line) + 1
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
#: Câte constatări se CER bazei pentru un mesaj. Ceea ce se cere e de ordinul a
#: ceea ce se poate afișa: comanda cerea 200 de rânduri, tipărea 20 și scria
#: „200 afișate" — pe gazda de producție, cu 1055 deschise, singura cifră
#: adevărată din propoziția aia era că erau vulnerabilități.
#:
#: Nu e o promisiune că se arată 20. Câte intră îl decide `fit_blocks`, în
#: funcție de cât de lungi sunt chiar rândurile cerute: pe datele reale ale
#: gazdei încap **17** din cele 20 (referințe de imagine lungi și trei legături
#: CVE pe rând), iar antetul spune 17. Plafonul e aici ca să nu se ceară bazei
#: un ordin de mărime peste ce poate încăpea vreodată; un test cere ca pe
#: rânduri scurte să intre toate 20, altfel numărul ăsta n-ar descrie nimic.
VULN_LIMIT = 20

#: Cât din eticheta „pe ce stă" intră pe un rând de listă. `describe` întoarce
#: referința imaginii verbatim și numele aplicației dintr-o cale — amândouă
#: scrise de scaner peste text pe care nu-l controlăm. Fără plafon, o singură
#: constatare cu o cale lungă mănâncă locul altor cinci.
MAX_SUBJECT_LIST = 44

#: Același lucru în detaliul unei singure constatări, unde e loc de mai mult.
MAX_SUBJECT_DETAIL = 120

#: Cât ocupă numele unui pachet sau o versiune pe un rând de listă. `package`
#: și `fixed_version` vin dintr-un manifest scanat sub un web root, deci
#: lungimea lor o alege cine scrie manifestul. Nemărginite, o singură
#: constatare poate depăși singură tot bugetul mesajului, iar lista de
#: dedesubt rămâne goală cu antetul spunând cinstit „0 afișate".
MAX_FIELD_LIST = 56

#: Cât din identificatorul CVE intră pe un rând. Al patrulea câmp netrusted de
#: pe rândul ăla, și singurul rămas nemărginit: `cve_html` cade pe
#: `escape(str(cve))` pentru orice nu e un CVE bine format, fără plafon, iar o
#: singură constatare cu un „CVE" de 4 kB în vârful priorității golea lista
#: (antet „0 afișate", zero rânduri — cinstit, dar inutil). Măsurat pe ambele
#: gazde: `max(length(cve))` e 14. 32 lasă loc și pentru GHSA și DLA.
MAX_CVE_LIST = 32

#: Cât din argumentul neînțeles se citează înapoi operatorului. Ca la pagină:
#: un mesaj care repetă întreg ce i s-a dat e un mesaj a cărui lungime o alege
#: altcineva.
MAX_ECHO = 40


@dataclass(frozen=True)
class VulnFilter:
    """Ce a cerut argumentul lui `/vulnerabilitati`, tradus o singură dată.

    `severities`/`kev_only`/`kind` merg în SQL; `title` și `scope` sunt ce
    citește operatorul. Toate patru ies din aceeași potrivire, deci antetul nu
    poate numi altă mulțime decât cea interogată.

    `warning` e nevid când argumentul n-a putut fi onorat. Un filtru
    neînțeles se SPUNE: 1055 de rânduri sub un titlu pe care operatorul a cerut
    să-l restrângă e aceeași minciună ca zero rânduri.
    """

    title: str
    scope: str
    severities: tuple[str, ...] | None = None
    kev_only: bool = False
    kind: str | None = None
    warning: str | None = None

    @property
    def filtered(self) -> bool:
        return self.severities is not None or self.kev_only or self.kind is not None


# Argumentele pe categorie oglindesc `?asociat=` din pagină, dar în cuvintele
# pe care le tastează operatorul. Nu e o a doua clasificare: aliasul duce la
# `kind`-ul lui `scan.subject`, iar scanerele categoriei vin tot din
# `subject.categories`, măsurate în bază. Cu și fără diacritice, fiindcă un
# argument e text liber și „aplicație" e felul firesc de a-l scrie.
#: Cuvintele de filtru pe care botul le ANUNȚĂ — în coada listei și în /ajutor.
#: Una singură, fiindcă două liste care se pot despărți înseamnă un ajutor care
#: oferă un cuvânt refuzat de comandă, sau un cuvânt care merge și despre care
#: nu află nimeni. Un test cere ca fiecare cuvânt de aici să fie înțeles de
#: `parse_vuln_filter`, ca fiecare categorie din `subject.KINDS` să fie
#: accesibilă prin cel puțin unul dintre ele, și ca `HELP` să le listeze pe
#: exact acestea.
FILTER_WORDS: tuple[str, ...] = ("kev", "critice", "mari", "sistem", "container",
                                 "aplicatie", "necunoscut")

_KIND_ARGS: dict[str, str] = {
    "sistem": KIND_OS, "os": KIND_OS, "sistem-de-operare": KIND_OS,
    "container": KIND_CONTAINER, "containere": KIND_CONTAINER,
    "aplicatie": KIND_APP, "aplicație": KIND_APP, "aplicatii": KIND_APP,
    "aplicații": KIND_APP, "app": KIND_APP,
    "necunoscut": KIND_UNKNOWN, "unknown": KIND_UNKNOWN,
}


def parse_vuln_filter(arg: str) -> VulnFilter:
    """Argumentul, în ce se interoghează și în ce se scrie în antet.

    Pură, ca să poată fi verificată fără bază de date: aici se decide și ce
    mulțime se cere, și cum se numește ea pe ecran, iar dacă cele două ar fi
    scrise în locuri diferite s-ar putea despărți.
    """
    a = arg.strip().lower()
    if not a:
        return VulnFilter("Vulnerabilități deschise", "deschise")
    if a in ("kev", "exploatate"):
        return VulnFilter("Vulnerabilități exploatate activ (KEV)",
                          "deschise exploatate activ", kev_only=True)
    if a in ("critice", "critical"):
        return VulnFilter("Vulnerabilități critice", "critice deschise",
                          severities=("critical",))
    if a in ("mari", "high"):
        return VulnFilter("Vulnerabilități critice și mari",
                          "critice sau mari deschise",
                          severities=("critical", "high"))
    if a in _KIND_ARGS:
        kind = _KIND_ARGS[a]
        label = KIND_LABELS[kind]
        return VulnFilter(f"Vulnerabilități · {label}",
                          f"deschise în „{label}”", kind=kind)
    return VulnFilter(
        "Vulnerabilități deschise", "deschise",
        warning=f"Filtru neînțeles: „{_echo(arg)}”. Se arată toate categoriile.")


def _echo(value: str) -> str:
    """Valoarea, scurtată, pentru un mesaj care o citează înapoi."""
    return value if len(value) <= MAX_ECHO else value[:MAX_ECHO] + "…"


def _trim(value: Any, width: int) -> str:
    """Textul BRUT, mărginit la `width` caractere. Nu escapează nimic.

    Separat de `_short` fiindcă are un al doilea apelant: `cve_html` escapează
    el însuși ce primește, deci acolo trebuie dată valoarea netrecută prin
    `esc` — altfel un `&` ajunge `&amp;amp;` pe ecran.
    """
    text = "" if value is None else str(value)
    return text if len(text) <= width else text[:width - 1] + "…"


def _short(value: Any, width: int) -> str:
    """Textul, mărginit la `width` și abia apoi escapat.

    Ordinea contează, și e singurul motiv pentru care funcția asta există:
    tăiat DUPĂ escapare, `&lt;` rămâne `&l`, Telegram refuză mesajul întreg, și
    un singur rând ostil oprește alerta, nu doar rândul lui. Tăiat înainte,
    `width` numără și caracterele pe care operatorul chiar le vede — un
    `&lt;a&gt;` ocupă 4 caractere din buget, nu 12.
    """
    return esc(_trim(value, width))


def _subject_line(row: dict, *, width: int) -> str:
    """Pe ce stă constatarea — sistem de operare, imagine, aplicație.

    `scan.subject.describe`, aceeași funcție care umple coloana „Asociat cu"
    din pagină. O a doua hartă scaner→categorie aici ar fi exact felul în care
    botul și panoul ajung să spună lucruri diferite despre același rând, adică
    ce se repară acum.
    """
    return _short(describe(row.get("scanner"), row.get("location")).label, width)


def fit_blocks(blocks: list[list[str]], budget: int) -> list[list[str]]:
    """Blocurile care încap întregi în `budget` unități UTF-16.

    Unități, nu caractere: `w16`, aceeași măsură ca `clamp` și ca rezervarea
    din apelant. Trei socoteli în două unități ar lăsa nemărginită exact felia
    dintre ele.

    Un bloc e o constatare, cu toate liniile ei. Se taie între constatări, nu
    prin mijlocul uneia — o constatare fără rândul ei de pachet arată ca o
    constatare fără pachet.

    EXISTĂ ca antetul să poată număra ce s-a tipărit cu adevărat. Dacă
    scurtarea ar rămâne în seama lui `clamp`, numărul din antet ar fi scris
    înainte să se știe câte rânduri intră, iar mesajul ar spune din nou mai
    mult decât arată — de data asta cu 20 în loc de 200.
    """
    kept: list[list[str]] = []
    used = 0
    for block in blocks:
        cost = sum(w16(line) + 1 for line in block)
        if used + cost > budget:
            break
        kept.append(block)
        used += cost
    return kept


async def cmd_vulns(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Open findings, most urgent first, with a filter argument.

    Ordered by the prioritisation score rather than by CVSS: a critical CVE in
    something not exposed matters less than a medium one being exploited in the
    wild right now, and the score is what already encodes that.

    Trei cantități, măsurate pe gazda de producție la 21 septembrie 2026 și
    până acum amestecate în una singură: câte se ARATĂ (20), câte sunt în
    mulțimea cerută (477 pe sistemul de operare) și câte sunt deschise în total
    (1055). Un mesaj care spune doar una dintre ele se citește ca și cum ar fi
    toate trei.

    Filtrele merg în SQL, înaintea lui `LIMIT`. Filtrate în Python pe rândurile
    deja tăiate, `/vulnerabilitati critice` răspundea cu „criticele dintre
    primele 200 după prioritate" — o mulțime care pe gazda reală nu conține
    niciun pachet al sistemului, fiindcă primul rând `dnf` e al 373-lea.
    """
    db: Database = context.bot_data["db"]
    sel = parse_vuln_filter(context.args[0] if context.args else "")

    # Categoriile se numără peste TOATE rândurile deschise, iar `total_open` e
    # suma aceleiași măsurători — deci „din N în categorie" și „din M în total"
    # nu pot proveni din două numărători care nu se adună.
    cats = categories(await findings_repo.open_counts_by_scanner(db))
    total_open = sum(c.count for c in cats)

    scanners: list[str] | None = None
    warnings: list[str] = [sel.warning] if sel.warning else []
    if len(context.args or ()) > 1:
        # Un singur selector pe comandă. Al doilea cuvânt nu se poate onora,
        # deci se SPUNE: de când coada listei anunță șapte filtre,
        # `/vulnerabilitati critice sistem` e o tastare firească, iar tăcerea
        # ar da un răspuns despre toate categoriile sub un cuvânt care cerea
        # una singură.
        warnings.append(
            f"Se ia un singur filtru, „{_echo(context.args[0])}”. "
            f"Restul argumentelor nu au fost folosite.")
    if sel.kind is not None:
        cat = next((c for c in cats if c.kind == sel.kind), None)
        if cat is None:
            # Un alias care duce la un `kind` pe care `subject.categories` nu-l
            # mai produce. Nu se poate întâmpla azi (`KINDS` le acoperă pe
            # toate), și tocmai de-aia se spune, în loc să se arate tot.
            sel = parse_vuln_filter("")
            warnings.append("Categoria cerută nu mai există. Se arată toate categoriile.")
        else:
            # Lista, chiar goală, înseamnă „numai scanerele categoriei" —
            # niciodată „fără filtru". Vezi `_scanner_clause`.
            scanners = list(cat.scanners)

    severities = list(sel.severities) if sel.severities is not None else None
    counts = await findings_repo.open_counts(
        db, scanners=scanners, severities=severities, kev_only=sel.kev_only)
    rows = await findings_repo.list_open(
        db, limit=VULN_LIMIT, scanners=scanners, severities=severities,
        kev_only=sel.kev_only)
    # Trei dus-întorsuri, nu o tranzacție: o scanare care se termină între ele
    # poate lăsa „20 afișate din 19" pentru o singură apăsare. Aceeași alegere
    # ca pagina — o tranzacție în jurul unei citiri costă mai mult decât cazul
    # cel mai rău, iar cifrele rămân măsurate, nu netezite.
    selected_total = int(counts.get("total", 0))

    warn_lines = ([f"⚠️ <i>{esc(w)}</i>" for w in warnings] + [""]) if warnings else []

    if not rows:
        empty = [f"✅ <b>{sel.title}</b>: niciuna."]
        if sel.filtered:
            # „Nimic în categoria asta" lângă 1055 deschise e altceva decât
            # „nimic deschis", și numai a doua e o veste bună.
            empty.append(f"<i>{total_open} deschise în total — /vulnerabilitati "
                         f"le arată pe cele mai prioritare.</i>")
        else:
            empty.append("<i>Scanarea rulează nocturn; /vuln &lt;id&gt; pentru detaliu.</i>")
        await _reply(update, clamp(warn_lines + empty))
        return

    head = " · ".join(
        f"{_SEV_EMOJI[s]}{counts[s]}"
        for s in ("critical", "high", "medium", "low", "info")
        if counts.get(s)) or "—"
    if counts.get("kev"):
        head += f" · 🔥 {counts['kev']} KEV"

    blocks: list[list[str]] = []
    for r in rows:
        kev = " 🔥" if r.get("kev") else ""
        # `_trim` pe valoarea brută: `cve_html` escapează el ce primește.
        ref = cve_html(_trim(r.get("cve"), MAX_CVE_LIST),
                       rpm=(r.get("scanner") == "dnf"), kev=bool(r.get("kev")))
        blocks.append([
            f"{_SEV_EMOJI.get(r['severity'], '⚪')} <b>#{r['id']}</b> {ref}{kev}",
            f"   <code>{_short(r.get('package') or r.get('location') or '?', MAX_FIELD_LIST)}</code>"
            f" → {_short(r.get('fixed_version') or 'fără fix cunoscut', MAX_FIELD_LIST)}"
            f" · prio {r.get('priority', 0)}"
            f" · {_subject_line(r, width=MAX_SUBJECT_LIST)}",
        ])

    tail = ("\n/vuln &lt;id&gt; · /planifica &lt;id&gt; pentru un plan"
            "\n<i>filtre: " + " · ".join(FILTER_WORDS) + "</i>")

    # Bugetul se rezervă cu numerele CELE MAI MARI pe care le pot lua antetul
    # și nota de coadă (toate rândurile cerute, toate cele nearătate), deci
    # rescrierea lor cu numerele reale nu poate decât să scurteze mesajul.
    # Invers — rezervat pe mic și rescris pe mare — ar trece peste limită, iar
    # Telegram refuză mesajul întreg.
    def _head_lines(shown: int) -> list[str]:
        scope = f"{shown} afișate din {selected_total} {sel.scope}"
        if sel.filtered:
            scope += f" · {total_open} deschise în total"
        return [*warn_lines, f"🛠️ <b>{sel.title}</b>", head, f"<i>{scope}</i>", ""]

    def _rest_note(shown: int) -> list[str]:
        missing = selected_total - shown
        return ([f"\n<i>…și încă {missing} neafișate. Panoul web le are pe toate.</i>"]
                if missing > 0 else [])

    # `+ 1` la coadă: `clamp` o lipește cu un `\n` în plus față de lungimea ei.
    # Totul în unități UTF-16, ca `clamp` și `fit_blocks` — trei socoteli în
    # două unități ar lăsa exact felia dintre ele nemărginită.
    reserved = sum(w16(line) + 1 for line in _head_lines(len(rows))) + w16(tail) + 1
    reserved += sum(w16(line) + 1 for line in _rest_note(0))
    kept = fit_blocks(blocks, MAX_MESSAGE - reserved)

    shown = len(kept)
    lines = [*_head_lines(shown),
             *(line for block in kept for line in block),
             *_rest_note(shown)]
    await _reply(update, clamp(lines, tail=tail))


async def cmd_vuln(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Detaliul unei constatări, căutat după id în bază — nu într-o listă.

    Comanda citea primele 1000 de rânduri deschise și căuta id-ul printre ele.
    Pe gazda de producție, cu 1055 deschise, ultimele 55 nu se puteau deschide
    deloc: răspunsul era „inexistentă sau deja rezolvată" pentru o
    vulnerabilitate care exista și era deschisă. `get_finding` ia rândul după
    cheia primară, deci nu există „prea departe în listă".

    Și separă cele două stări pe care mesajul ăla le amesteca: o constatare
    rezolvată e un fapt diferit de un id inexistent, iar operatorul care tocmai
    a citit un id dintr-o alertă are nevoie să știe care dintre ele e.
    """
    db: Database = context.bot_data["db"]
    # `parse_id`, nu `.isdigit()`: id-ul ăsta ajunge acum în bază, unde coloana
    # e `bigint`. `9223372036854775808` are 19 cifre ASCII, trece de `isdigit()`
    # și de `int()`, iar asyncpg îl refuză pe fir cu `DataError` — adică o
    # excepție în handler și „A apărut o eroare la procesarea comenzii" în loc
    # de un răspuns. Vezi `sentinel/util/ids.py`.
    fid = parse_id(context.args[0]) if context.args else None
    if fid is None:
        await _reply(update, "Folosire: <code>/vuln &lt;id&gt;</code> — id-ul din /vulnerabilitati")
        return

    row = await findings_repo.get_finding(db, fid)
    if row is None:
        await _reply(update, f"Vulnerabilitatea #{fid} nu există. Lista: /vulnerabilitati")
        return

    deschisa = row.get("status") == "open"
    rpm = row.get("scanner") == "dnf"
    lines = [
        f"{_SEV_EMOJI.get(row['severity'], '⚪')} <b>Vulnerabilitate #{row['id']}</b>"
        + (" · 🔥 <b>exploatată activ</b>" if row.get("kev") else ""),
        f"<b>{esc(row.get('title'))}</b>",
    ]
    if not deschisa:
        lines.append(f"⚪ <i>Nu mai e deschisă (stare: {esc(row.get('status'))}) — "
                     f"ce urmează e ultima constatare, nu starea de acum.</i>")
    lines += [
        "",
        f"Asociat cu: {_subject_line(row, width=MAX_SUBJECT_DETAIL)}",
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

    if not deschisa:
        lines.append("\n<i>Nu mai e deschisă — un plan pentru ea ar repara ceva "
                     "ce scanarea nu mai vede.</i>")
    elif row.get("fixed_version"):
        # `/planifica`, nu `/patch`: `/patch <id>` deschide PLANUL cu id-ul ăla,
        # iar aici id-ul e al unui finding. Linia asta trimitea operatorul să
        # tasteze un id de vulnerabilitate într-o comandă care citește id-uri de
        # plan — pe gazda reală, cu 4 planuri și 1028 de findinguri, răspunsul
        # era „Plan inexistent." sau, mai rău, planul altcuiva.
        lines.append(f"\nCere un plan: <code>/planifica {row['id']}</code>")
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
    cfg = context.bot_data["cfg"]
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
        lines.append(_format_event(e, with_ip=src_ip is None,
                                   tz_name=cfg.timezone))

    tail = ("\n<i>/evenimente &lt;ip&gt; pentru o singură sursă</i>"
            if not src_ip else f"\n<code>/block {esc(src_ip)}</code> pentru a bloca")
    await _reply(update, clamp(lines, tail=tail))


def _format_event(e: dict, *, with_ip: bool, tz_name: str | None) -> str:
    """One event, one line. Every field here is attacker-influenced."""
    # Marcajul de fus stă pe FIECARE rând, nu o dată în antet. Cinci caractere
    # pe rând sunt mai ieftine decât un antet care devine mincinos în noaptea
    # schimbării ceasurilor, când aceeași listă conține și EET, și EEST.
    when = tz.fmt(e["ts"], "%H:%M:%S", tz_name=tz_name)
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
/vulnerabilitati [kev|critice|mari|sistem|container|aplicatie|necunoscut] — findings deschise, prioritizate
/vuln &lt;id&gt; — detaliu, cu legături către NVD și Red Hat

<b>Patch-uri</b>
/patches — planuri în așteptare
/patch &lt;id&gt; — planul, cu butoane de aprobare
/planifica &lt;id vuln&gt; — cere un plan pentru o vulnerabilitate anume

<b>Trafic și servicii</b>
/evenimente [ip] — evenimente brute
/servicii — fiecare serviciu, up/down și uptime

<b>Răspuns</b>
/block &lt;ip&gt; [ttl] [motiv] · /unblock &lt;ip&gt;
/blocklist — ce e blocat acum
/panic — golește tot blocklist-ul (dublă confirmare)

<b>Notificări</b>
/mute 22:00-06:00 · /mute 2h · /unmute
<i>Criticele, PANIC și eșecurile de patch trec oricum.</i>

<b>Întrebări</b>
/intreaba &lt;întrebare&gt; — răspuns din datele reale, în cuvinte proprii"""


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
    cfg = context.bot_data["cfg"]
    blocks = await blocklist_repo.list_active(db, limit=60)
    live = await actions.live_count()

    if not blocks:
        await _reply(update, f"🚫 <b>Blocklist gol.</b>\n"
                             f"nftables: {live if live >= 0 else '?'} elemente")
        return

    lines = [f"🚫 <b>Blocklist</b> — {len(blocks)} în bază · "
             f"{live if live >= 0 else '?'} în nftables", ""]
    for b in blocks:
        exp = tz.fmt(b.expires_at, tz_name=cfg.timezone, missing="permanent")
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
    cfg = context.bot_data["cfg"]
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
                             f"{tz.fmt(r['first_seen'], tz_name=cfg.timezone)}")

    await update.effective_message.reply_html(clamp("\n".join(lines)))
