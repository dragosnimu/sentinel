"""Anunțul de vulnerabilități noi, imediat după scanare.

Cerut de operator pe 21 august 2026. Până atunci, o scanare care descoperea
douăzeci de CVE-uri exploatate activ nu spunea nimănui nimic: numerele intrau în
bază și așteptau ca cineva să deschidă panoul. Jurnalul avea o linie `INFO`, care
e chiar categoria pe care nimeni n-o citește.

## Ce se anunță, și de ce nu tot

Doar constatările NOI ale rulării curente — cele pentru care `upsert_finding` a
întors „a fost inserată". O scanare care regăsește aceleași două sute de
constatări nu trimite nimic: un canal care repetă aceeași listă la fiecare
rulare e un canal pe care operatorul îl oprește, iar atunci se pierde și alarma
care conta.

## De ce mesajul e mărginit

`MAX_LISTED` intrări, apoi „și încă N". O scanare de pe o gazdă neîngrijită
poate produce câteva sute de constatări noi la prima rulare, iar Telegram taie
mesajele lungi — tăiat de Telegram, mesajul pierde tocmai coada, care aici e
numărul total. Mărginit aici, coada e numărul, iar lista e vârful.

Ordinea: KEV întâi, apoi prioritatea. `kev` înseamnă „se exploatează chiar
acum", iar dacă din tot mesajul se citește un singur rând, ăla trebuie să fie.

## De ce nu aruncă niciodată

Un anunț care oprește scanarea ar transforma un canal de informare într-un mod
de eșec: scanarea e treaba, anunțul e despre ea. `send_to_chats` nu ridică
excepții prin construcție, iar restul e învelit — vezi `announce`.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Sequence

log = logging.getLogger("sentinel.scan.announce")

#: Câte constatări se enumeră în mesaj înainte de „și încă N".
MAX_LISTED = 10

#: Cât se așteaptă după Telegram. Mai scurt decât timeout-ul unei scanări,
#: fiindcă un anunț care întârzie scanarea următoare e mai scump decât unul
#: pierdut: următoarea rulare îl va conține oricum, `first_seen` nu se mișcă.
TIMEOUT_S = 15.0


def _rank(finding: dict[str, Any]) -> tuple[int, int]:
    """Cheia de sortare: KEV întâi, apoi prioritatea, descrescător.

    Tuplu, nu un scor combinat: un scor ar fi trebuit să aleagă un factor prin
    care KEV cântărește cât un salt de prioritate, iar numărul ăla n-are de unde
    să vină. Cu tuplul, regula se citește — nimic nu trece înaintea a ceva ce se
    exploatează acum.
    """
    kev = 1 if finding.get("kev") else 0
    try:
        # `finding.get("priority") or 0` ar fi scurtcircuitat ÎNAINTE de `try`,
        # iar o prioritate absentă ar fi devenit zero — adică exact ce spune
        # comentariul de mai jos că nu trebuie să se întâmple. Prins de test.
        priority = int(finding["priority"])
    except (KeyError, TypeError, ValueError):
        # O prioritate ilizibilă NU e zero: zero ar trimite constatarea la coada
        # listei ca și cum ar fi fost evaluată și găsită neimportantă. Se ridică
        # la mijloc, ca să fie văzută și corectată.
        priority = 50
    return (kev, priority)


def build_message(findings: Sequence[dict[str, Any]], *, host: str) -> str:
    """Mesajul, ca text HTML pentru Telegram. Funcție PURĂ.

    Separată de trimitere ca să poată fi probată fără rețea: forma unui mesaj e
    ce citește operatorul la 3 dimineața, iar un test care are nevoie de un bot
    ca să verifice o virgulă nu se scrie niciodată.
    """
    total = len(findings)
    ordered = sorted(findings, key=_rank, reverse=True)
    kev_count = sum(1 for f in ordered if f.get("kev"))

    head = f"🔎 <b>{_esc(host)} — {total} vulnerabilități noi</b>"
    if kev_count:
        # Numărul KEV în TITLU, nu doar în listă: e singura cifră care schimbă ce
        # face operatorul în următoarele minute.
        head += f"\n<b>{kev_count} se exploatează activ (KEV).</b>"

    lines = [head, ""]
    for finding in ordered[:MAX_LISTED]:
        mark = "🔴" if finding.get("kev") else "•"
        cve = _esc(finding.get("cve") or "fără CVE")
        pkg = _esc(finding.get("package") or "?")
        installed = _esc(finding.get("installed_version") or "?")
        fixed = finding.get("fixed_version")
        fix = f" → {_esc(str(fixed))}" if fixed else " (fără fix publicat)"
        sev = _esc(str(finding.get("severity") or "?"))
        lines.append(f"{mark} <code>{cve}</code> {sev} — {pkg} {installed}{fix}")

    if total > MAX_LISTED:
        lines.append(f"\n…și încă {total - MAX_LISTED}. Lista întreagă e în panou.")
    return "\n".join(lines)


def _esc(value: Any) -> str:
    """Escapare HTML pentru Telegram.

    Valorile vin din ieșirea unui scaner, adică din nume de pachete și texte de
    advisory — nu din trafic, dar nici scrise de noi. Un `<` netratat rupe
    mesajul întreg, iar Telegram răspunde cu 400: alarma s-ar pierde din cauza
    unui caracter dintr-un nume de pachet.
    """
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


async def announce(cfg: Any, findings: Iterable[dict[str, Any]]) -> int:
    """Trimite anunțul. Întoarce câte chat-uri l-au primit.

    Zero e un răspuns valid și obișnuit: nicio constatare nouă, canalul oprit din
    configurație, fără token, fără chat-uri. Niciunul dintre ele nu e o eroare a
    scanării.

    Livrarea se verifică PER CHAT, nu prin absența unei excepții: un 400 de la
    Telegram — „chat not found", „bot was blocked by the user" — arată exact ca
    un succes dacă te uiți doar la faptul că apelul s-a întors.
    """
    items = list(findings)
    if not items:
        return 0
    if not getattr(cfg.scan, "announce_new", True):
        return 0

    try:
        from sentinel.config import get_secrets
        from sentinel.telegram.direct import send_to_chats
        from sentinel.telegram.identity import stamp, tag_for

        token = get_secrets().get("TELEGRAM_BOT_TOKEN")
        chats = list(cfg.telegram.allowed_chat_ids or [])
        if not token or not chats:
            log.info("anunț de vulnerabilități sărit: fără token sau fără chat")
            return 0

        host = getattr(cfg, "hostname", None) or "serverul monitorizat"
        # Numele instanței se pune AICI, nu în `build_message`: calea asta
        # ocolește botul, deci și `StampingBot`, care marchează tot ce pleacă
        # prin proces. `host` de mai sus e o etichetă din configurație și nu
        # deosebește două instalări — pe 27 august 2026 două Sentinel-uri au
        # alertat în același chat și niciun mesaj nu spunea de pe care mașină
        # venea. Vezi `sentinel/telegram/identity.py`.
        text = stamp(build_message(items, host=str(host)), tag_for(cfg))
        outcomes = await send_to_chats(
            token, chats, text, parse_mode="HTML", timeout_s=TIMEOUT_S)

        delivered = [o.chat_id for o in outcomes if o.ok]
        failed = [o.describe() for o in outcomes if not o.ok]
        if delivered:
            log.warning("anunț de vulnerabilități noi trimis",
                        extra={"chats": ",".join(str(c) for c in delivered),
                               "findings": len(items)})
        if failed:
            log.error("anunțul de vulnerabilități nu a ajuns la fiecare chat",
                      extra={"detail": "; ".join(failed)})
        return len(delivered)
    except Exception as exc:  # noqa: BLE001 - un anunț nu are voie să pice scanarea
        log.error("anunțul de vulnerabilități a eșuat",
                  extra={"detail": str(exc)[:200]})
        return 0
