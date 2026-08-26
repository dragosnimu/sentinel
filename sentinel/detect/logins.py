"""Ce se anunță când cineva se loghează, și ce se tace.

## Regula, într-o propoziție

Fiecare sesiune INTERACTIVĂ produce un mesaj la deschidere și un rezumat la
închidere. Nimic altceva nu produce mesaje.

## De ce numai cele interactive

Măsurat pe gazda de producție, pe șapte zile: **557 de sesiuni fără terminal**
(deploy, rsync, diagnostic — fiecare rulare a scriptului de livrare deschide vreo
zece) și **29 cu terminal**, adică vreo patru pe zi. O alertă pe fiecare sesiune
ar fi însemnat ~80 de mesaje pe zi, dintre care 75 despre propriile automatizări.

Un canal care produce optzeci de mesaje pe zi e un canal pe care îl oprești
într-o săptămână, iar un canal oprit e mai rău decât niciunul: arată ca acoperire
și nu e. Aceeași judecată e scrisă în `telegram/quiet.py` despre orele de
liniște, și e aceeași aici.

Ce se pierde, spus pe față: cine are cheia și rulează `ssh gazdă 'comandă'` nu
produce niciun mesaj. Comenzile lui SE ÎNREGISTREAZĂ — istoricul e complet —, dar
nimeni nu e trezit. Reparația adevărată e un cont separat pentru automatizări,
livrat odată cu asta: după el, „fără terminal" și „contul de deploy" sunt același
lucru, iar o sesiune fără terminal pe contul TĂU redevine o surpriză.

## Ce face o logare neașteptată

Cont, adresă sau oră nemaivăzute. Se învață singure din ce se întâmplă, iar în
prima `LEARNING_DAYS` zile nu se ridică niciun incident — altfel prima săptămână
ar produce un incident la fiecare logare, exact când încă nu știi dacă sistemul e
de încredere. Mesajele pleacă normal și în fereastra aia; se ține doar incidentul.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

#: Cât ține fereastra de învățare a liniei de referință.
#:
#: Două săptămâni: destul cât să prindă și tiparul de weekend, și o săptămână de
#: concediu în care nu te-ai logat de acasă. Mai scurt, prima logare de sâmbătă
#: ar fi o surpriză; mai lung, luni întregi fără nicio protecție.
LEARNING_DAYS = 14

#: Felul vestii, pentru `notifications.kind`. Trebuie să fie și în
#: `telegram.quiet.NEVER_MUTED_KINDS` — garda din teste cere amândouă.
KIND = "login"

#: Orele considerate obișnuite fără nicio învățare.
#:
#: Nu e o linie de referință, e o margine: ora se învață ca oricare alt fapt, dar
#: o logare la 4 dimineața rămâne o surpriză chiar dacă s-a mai întâmplat de
#: două ori. Fereastra e largă dinadins — cine lucrează seara nu are de ce să
#: primească o alertă în fiecare seară.
ODD_HOURS = frozenset(range(1, 6))

#: De câte ori trebuie văzut un fapt ca să nu mai fie o surpriză.
#:
#: Unu. A doua oară nu mai e nou, iar un prag mai mare ar însemna că a doua
#: logare de pe o adresă de atacator e tăcută.
FAMILIAR_AFTER = 1


async def learning_until(db: Database) -> datetime | None:
    """Când se încheie fereastra de învățare, sau `None` dacă n-a început.

    Pornește de la cel mai vechi fapt din linia de referință, nu de la o dată
    scrisă separat: o dată ținută aparte s-ar putea desincroniza de conținut, iar
    atunci fereastra ar spune «am învățat» despre o tabelă goală.
    """
    started = await db.fetchval("SELECT min(first_seen) FROM login_baseline")
    return None if started is None else started + timedelta(days=LEARNING_DAYS)


async def _seen_before(db: Database, kind: str, value: str) -> bool:
    """A mai fost văzut faptul ăsta — ȘI îl înregistrează.

    Citirea și scrierea într-o singură instrucțiune, dinadins: două apeluri
    separate lasă o fereastră în care aceeași logare, procesată de două ori după
    o repornire, ar fi „nouă" a doua oară.

    `xmax = 0` e felul lui PostgreSQL de a spune «rândul ăsta a fost INSERAT
    acum», nu actualizat. E singura cale de a deosebi cele două cazuri fără o a
    doua interogare.
    """
    row = await db.fetchrow(
        """
        INSERT INTO login_baseline (kind, value)
        VALUES ($1, $2)
        ON CONFLICT (kind, value) DO UPDATE
            SET last_seen = now(), seen_count = login_baseline.seen_count + 1
        RETURNING seen_count, (xmax = 0) AS inserted
        """,
        kind, value)
    if row is None:
        return False
    return not row["inserted"] and row["seen_count"] > FAMILIAR_AFTER


async def classify(db: Database, session: dict[str, Any]) -> list[str]:
    """Ce e neașteptat la sesiunea asta. Lista goală înseamnă „nimic".

    Fiecare fapt se înregistrează în linia de referință chiar dacă e nou — de
    asta a doua logare de pe aceeași adresă nu mai surprinde. Consecința, spusă
    pe față: o adresă de atacator devine „obișnuită" după prima ei logare. Ce
    face asta suportabil e că PRIMA a produs și mesaj, și incident.
    """
    surprize: list[str] = []

    cont = session.get("username")
    if cont and not await _seen_before(db, "account", cont):
        surprize.append(f"cont nemaivăzut: {cont}")

    ip = session.get("src_ip")
    if ip and not await _seen_before(db, "src_ip", str(ip)):
        surprize.append(f"adresă nemaivăzută: {ip}")

    opened = session.get("opened_at")
    if isinstance(opened, datetime) and opened.astimezone(timezone.utc).hour in ODD_HOURS:
        # Ora NU trece prin linia de referință: e o margine, nu un obicei. Cine
        # se loghează la 4 dimineața de trei ori nu face ora aia obișnuită.
        surprize.append(f"oră nefirească: {opened.astimezone(timezone.utc):%H:%M} UTC")

    return surprize


# ---------------------------------------------------------------------------
# Mesajele
# ---------------------------------------------------------------------------
def open_text(session: dict[str, Any], surprize: list[str]) -> str:
    cine = session.get("username") or "cont necunoscut"
    de_unde = session.get("src_ip") or "local"
    cand = session["opened_at"].astimezone(timezone.utc)
    linii = [
        "🔐 <b>Logare pe server</b>",
        f"Cont: <code>{cine}</code>",
        f"De la: <code>{de_unde}</code>",
        f"Terminal: <code>{session.get('terminal') or '—'}</code>",
        f"Când: {cand:%Y-%m-%d %H:%M} UTC",
    ]
    if surprize:
        linii.append("")
        linii.append("⚠️ <b>Neobișnuit:</b>")
        linii.extend(f"· {s}" for s in surprize)
    else:
        linii.append("")
        linii.append("Nimic neobișnuit: cont, adresă și oră cunoscute.")
    return "\n".join(linii)


def summary_text(session: dict[str, Any], varf: list[dict[str, Any]]) -> str:
    """Rezumatul de la închidere: cât a durat, ce s-a rulat.

    Comenzile privilegiate se arată pe nume; restul se numără. «412 comenzi» nu
    spune nimic, «412 comenzi, dintre care 3 cu sudo, și iată-le» spune ce s-a
    întâmplat.
    """
    cine = session.get("username") or "cont necunoscut"
    opened = session["opened_at"].astimezone(timezone.utc)
    closed = (session.get("closed_at") or opened).astimezone(timezone.utc)
    durata = closed - opened
    minute = int(durata.total_seconds() // 60)
    lungime = f"{minute // 60}h {minute % 60}m" if minute >= 60 else f"{minute}m"

    linii = [
        "🔓 <b>Sesiune încheiată</b>",
        f"Cont: <code>{cine}</code> · de la <code>{session.get('src_ip') or 'local'}</code>",
        f"Durată: {lungime} · {session.get('command_count', 0)} comenzi"
        f" · {session.get('sudo_count', 0)} privilegiate",
    ]
    # `command_count` numără rândurile care SUNT în tabelă, iar curățarea le poate
    # fi luat pe cele mai multe. Spus așa, mesajul rămâne adevărat și după ea: un
    # «0 comenzi» singur ar spune «n-a rulat nimic» despre un deploy de o jumătate
    # de milion de comenzi.
    sterse = session.get("commands_purged") or 0
    if sterse:
        linii.append(f"· și încă {sterse} șterse din istoric ca zgomot de "
                     f"automatizare")
    if varf:
        linii.append("")
        linii.append("<b>Comenzi privilegiate:</b>")
        for c in varf[:10]:
            linii.append(f"· <code>{_esc(str(c.get('argv') or '')[:160])}</code>")
        if session.get("sudo_count", 0) > 10:
            linii.append(f"· … și încă {session['sudo_count'] - 10}")
    return "\n".join(linii)


def _esc(text: str) -> str:
    """Escapare HTML pentru Telegram.

    Linia de comandă e text ales de cine rulează comanda. Un `<b>` în ea ar rupe
    mesajul, iar unul construit cu grijă l-ar putea face să spună altceva decât
    s-a întâmplat.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---------------------------------------------------------------------------
# Coada
# ---------------------------------------------------------------------------
_ENQUEUE = """
INSERT INTO notifications (channel, severity, kind, dedup_key, title, body, buttons)
VALUES ('telegram', $1::text, $2::text, $3::text, $4::text, $5::text, $6::jsonb)
"""


async def announce_new_sessions(db: Database) -> int:
    """Pune în coadă un mesaj pentru fiecare sesiune interactivă neanunțată.

    Starea trăiește în COLOANĂ (`alerted_at`), nu în memoria procesului: un bot
    repornit între citire și trimitere ar anunța a doua oară, iar unul repornit
    invers n-ar anunța deloc.
    """
    rows = await db.fetch(
        """
        SELECT id, session_key, username, host(src_ip) AS src_ip, terminal,
               opened_at, command_count, sudo_count
          FROM login_sessions
         WHERE alerted_at IS NULL AND interactive = true
         ORDER BY opened_at
        """)
    trimise = 0
    for row in rows:
        session = dict(row)
        surprize = await classify(db, session)
        # Severitatea vine din SURPRIZĂ, nu din faptul logării. O logare
        # obișnuită e o informație; una de pe o adresă nemaivăzută e altceva.
        severitate = "high" if surprize else "info"
        await db.execute(
            _ENQUEUE, severitate, KIND,
            f"login:{session['session_key']}:{session['opened_at'].isoformat()}",
            "Logare pe server", open_text(session, surprize),
            json.dumps(_buttons(session["id"], session.get("src_ip"))))
        await db.execute(
            "UPDATE login_sessions SET alerted_at = now(), unexpected = $2::text[] "
            "WHERE id = $1",
            session["id"], surprize)
        trimise += 1
    return trimise


async def summarise_closed_sessions(db: Database) -> int:
    """Rezumatul, pentru sesiunile închise care au fost anunțate la deschidere.

    `alerted_at IS NOT NULL` e condiția care contează: o sesiune pe care n-am
    anunțat-o (neinteractivă, sau văzută doar la ieșire) n-are ce rezuma. Fără
    ea, fiecare dintre cele 557 de sesiuni de deploy ar produce un mesaj la
    final — jumătate din zgomotul pe care tocmai l-am evitat, întors pe ușa din
    dos.
    """
    rows = await db.fetch(
        """
        SELECT id, session_key, username, host(src_ip) AS src_ip, terminal,
               opened_at, closed_at, command_count, sudo_count,
               commands_purged
          FROM login_sessions
         WHERE closed_at IS NOT NULL
           AND alerted_at IS NOT NULL
           AND summarised_at IS NULL
         ORDER BY closed_at
        """)
    trimise = 0
    for row in rows:
        session = dict(row)
        varf = await db.fetch(
            """
            SELECT argv FROM session_commands
             WHERE session_id = $1
               AND split_part(coalesce(exe, ''), '/', -1) = ANY($2::text[])
             ORDER BY id LIMIT 10
            """,
            session["id"], _privileged())
        await db.execute(
            _ENQUEUE, "info", KIND,
            f"logout:{session['session_key']}:{session['closed_at'].isoformat()}",
            "Sesiune încheiată", summary_text(session, [dict(v) for v in varf]),
            json.dumps([]))
        await db.execute(
            "UPDATE login_sessions SET summarised_at = now() WHERE id = $1",
            session["id"])
        trimise += 1
    return trimise


def _privileged() -> list[str]:
    from sentinel.db.repo.logins import PRIVILEGED
    return sorted(PRIVILEGED)


def _buttons(session_id: int, src_ip: str | None) -> list[dict[str, str]]:
    """Butoanele mesajului de logare.

    „Nu sunt eu" poartă identificatorul SESIUNII, nu adresa: adresa se citește la
    apăsare din rândul sesiunii, iar sesiunea e ce trebuie închisă. Un buton care
    ar purta adresa ar putea fi apăsat mult mai târziu, când alt om e conectat de
    pe ea.
    """
    b: list[dict[str, str]] = [{"text": "✔️ Am văzut", "data": "cancel"}]
    if src_ip:
        b.append({"text": "🚨 Nu sunt eu", "data": f"nteu:{session_id}"})
    return b
