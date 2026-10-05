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

## Culoarea, pe fiecare rând

Constatările aduc `risk_color` (evaluarea de la sfârșitul trecerii, vezi
`sentinel/scan/enrich.py`): punctul din fața rândului e semaforul — 🔴 Acum, 🟡
Curând, ⚪ Nedecis, 🟢 Ciclul obișnuit / De urmărit* —, iar 🔥 rămâne lângă cele din KEV. Un rând fără
culoare (o constatare care n-a trecut prin evaluare) păstrează forma veche: 🔴 doar
pentru KEV. Un KEV poate ieși VERDE: arborele CISA îl dă Track când exploatarea e
activă dar impactul e parțial și atacul nu e automatizabil, pe o misiune medie.
Nu se ascunde: 🟢 și 🔥 pe același rând spun exact asta.

## Trecerile în roșu — un singur mesaj, o singură dată

`announce_red` anunță constatările care au DEVENIT roșii după ce fuseseră evaluate
(vezi `enrich._announce_red` pentru regulile: nu prima evaluare, nu o constatare nouă
a scanării, nu a doua oară). Evaluarea se mișcă singură, când se mișcă datele (KEV,
punctele publicate de CISA); canalul se deschide doar pe urcări în roșu.

## De ce nu aruncă niciodată

Un anunț care oprește scanarea ar transforma un canal de informare într-un mod
de eșec: scanarea e treaba, anunțul e despre ea. `send_to_chats` nu ridică
excepții prin construcție, iar restul e învelit — vezi `announce`.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable, Sequence

log = logging.getLogger("sentinel.scan.announce")

#: Semaforul, pe culori. Același dicționar ca în `risk.py`, importat și nu
#: retipărit: două liste de emoji se despart la prima culoare mutată.
COLOR_EMOJI = {"red": "🔴", "amber": "🟡", "green": "🟢", "grey": "⚪"}

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
        color = finding.get("risk_color")
        if color:
            mark = COLOR_EMOJI.get(str(color), "⚪") + (" 🔥" if finding.get("kev") else "")
        else:
            mark = "🔴" if finding.get("kev") else "•"
        # Un aviz fără CVE structurat (`dnf list --security`, vezi
        # `os_packages._uncovered_advisories`) are `cve` nul, dar are ID-ul avizului:
        # mesajul e singurul loc unde operatorul află de el, iar „fără CVE" singur
        # nu-i spune ce să caute.
        cve = _esc(finding.get("cve") or finding.get("advisory_id") or "fără CVE")
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
    return await _deliver(cfg, lambda host: build_message(items, host=host),
                          label="de vulnerabilități noi", count=len(items))


def build_red_message(findings: Sequence[dict[str, Any]], *, host: str) -> str:
    """Mesajul „au devenit roșii". Funcție PURĂ.

    Scurt dinadins, ca reamintirea zilnică din `build_pending_reboot_reminder`: e un
    mesaj care se repetă când scorurile se mișcă, deci singurul pe care operatorul
    l-ar opri. Fiecare rând spune DE CE e roșu într-un singur motiv („KEV", „CISA:
    exploatat") și cât de grav e (CVSS, cu sursa lui); cele patru puncte de decizie și
    justificarea furnizorului sunt în `/vuln <id>`.

    Ordinea: după prioritate, descrescător; KEV-ul nu trece înaintea unui roșu fără
    KEV, fiindcă TOATE rândurile de aici sunt Act.
    """
    from sentinel.scan import risk_view

    total = len(findings)
    ordered = sorted(findings, key=lambda f: int(f.get("priority") or 0), reverse=True)
    # Numele STĂRII (`risk_view.COLOR_STATE_RO`), nu al culorii: același cuvânt ca pe rândul din
    # listă și din panou. „Acum (Act)": cuvântul de acțiune întâi, numele CISA în paranteză.
    state = risk_view.COLOR_STATE_RO["red"]
    noun = (f"vulnerabilitate a ajuns la „{state}”" if total == 1
            else f"vulnerabilități au ajuns la „{state}”")
    lines = [f"🔴 <b>{_esc(host)} — {total} {noun}</b>",
             f"<i>{risk_view.state_with_ssvc('red')}: decizia CISA SSVC cea mai urgentă — exploatare "
             "activă, atac automatizabil, impact total.</i>", ""]
    for finding in ordered[:MAX_LISTED]:
        cve = _esc(finding.get("cve") or finding.get("advisory_id") or "fără CVE")
        pkg = _esc(finding.get("package") or "?")
        risk = finding.get("risk") if isinstance(finding.get("risk"), dict) else {}
        why = _esc(risk_view.one_liner("red", risk))
        cvss = _esc(risk_view.fmt_cvss(risk.get("cvss")))
        ident = f" · /vuln {finding['id']}" if finding.get("id") else ""
        lines.append(f"🔴 <code>{cve}</code> — {pkg} · {why} · {cvss}{ident}")
    if total > MAX_LISTED:
        lines.append(f"\n…și încă {total - MAX_LISTED}. Lista întreagă e în panou.")
    lines.append("\n<i>Mesajul vine o singură dată pentru fiecare constatare; scorurile "
                 "se mișcă odată cu datele (KEV, CISA).</i>")
    return "\n".join(lines)


async def announce_red(cfg: Any, findings: Iterable[dict[str, Any]]) -> int:
    """Trimite mesajul „au devenit roșii". Întoarce câte chat-uri l-au primit.

    Aceleași reguli ca `announce`: comutatorul `scan.announce_new`, zero e un
    răspuns valid, livrarea numărată per chat, nimic nu ridică spre evaluare.
    Zero înseamnă și „nu a ajuns nicăieri", iar `enrich` retrage atunci
    revendicarea, ca trecerea următoare să reîncerce.
    """
    items = list(findings)
    if not items:
        return 0
    if not getattr(cfg.scan, "announce_new", True):
        return 0
    return await _deliver(cfg, lambda host: build_red_message(items, host=host),
                          label="de vulnerabilități devenite roșii", count=len(items))


async def _deliver(cfg: Any, build: Callable[[str], str], *, label: str,
                   count: int) -> int:
    """Calea unică spre Telegram a anunțurilor de după scanare.

    Un singur loc, fiindcă cele trei proprietăți care contează se strică una câte
    una când există două copii: mesajul e MARCAT cu numele instanței (calea asta
    ocolește botul, deci și `StampingBot` — vezi `sentinel/telegram/identity.py`),
    livrarea se numără PER CHAT, iar nimic de aici nu ridică spre scanare.
    `tests/security/test_telegram_names_its_instance.py` cere ca fiecare apelant
    al transportului direct să fie pe listă și să cheme `stamp`.
    """
    try:
        from sentinel.config import get_secrets
        from sentinel.telegram.direct import send_to_chats
        from sentinel.telegram.identity import stamp, tag_for

        token = get_secrets().get("TELEGRAM_BOT_TOKEN")
        chats = list(cfg.telegram.allowed_chat_ids or [])
        if not token or not chats:
            log.info(f"anunț {label} sărit: fără token sau fără chat")
            return 0

        host = getattr(cfg, "hostname", None) or "serverul monitorizat"
        # Numele instanței se pune AICI, nu în `build_message`: calea asta
        # ocolește botul, deci și `StampingBot`, care marchează tot ce pleacă
        # prin proces. `host` de mai sus e o etichetă din configurație și nu
        # deosebește două instalări — pe 27 august 2026 două Sentinel-uri au
        # alertat în același chat și niciun mesaj nu spunea de pe care mașină
        # venea. Vezi `sentinel/telegram/identity.py`.
        text = stamp(build(str(host)), tag_for(cfg))
        outcomes = await send_to_chats(
            token, chats, text, parse_mode="HTML", timeout_s=TIMEOUT_S)

        delivered = [o.chat_id for o in outcomes if o.ok]
        failed = [o.describe() for o in outcomes if not o.ok]
        if delivered:
            log.warning(f"anunț {label} trimis",
                        extra={"chats": ",".join(str(c) for c in delivered),
                               "findings": count})
        if failed:
            log.error(f"anunțul {label} nu a ajuns la fiecare chat",
                      extra={"detail": "; ".join(failed)})
        return len(delivered)
    except Exception as exc:  # noqa: BLE001 - un anunț nu are voie să pice scanarea
        log.error(f"anunțul {label} a eșuat", extra={"detail": str(exc)[:200]})
        return 0


# ---------------------------------------------------------------------------
# Reparația e pe disc, dar nu rulează: o decizie, nu un patch
# ---------------------------------------------------------------------------
#: Câte CVE-uri KEV se numesc în mesaj înainte de „și încă N".
MAX_KEV_LISTED = 5
#: Câte pachete se numesc în mesaj înainte de „și încă N".
MAX_PACKAGES_LISTED = 6

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_RO = {"critical": "critice", "high": "mari", "medium": "medii",
           "low": "mici", "info": "informative"}


def build_pending_reboot_message(items: Sequence[dict[str, Any]], *, host: str,
                                 running: str | None) -> str:
    """Mesajul „reparațiile sunt instalate, dar nu rulează". Funcție PURĂ.

    Cerut de operator pe 29 septembrie 2026, după patru zile în care a încercat să
    aplice cinci planuri de patch și a primit cinci refuzuri. Planurile erau
    răspunsul greșit la o întrebare care avea deja răspunsul pe disc: nucleul cu
    toate reparațiile era instalat, iar gazda rula unul mai vechi. Singurul lucru
    de făcut e o repornire, iar decizia ei e a operatorului.

    Ce trebuie să conțină, și de ce:

      * CE se închide — numărat pe CVE-uri DISTINCTE, cu severitatea cea mai mare
        a fiecăruia. Aceeași reparație apare pe cinci pachete (`kernel`,
        `kernel-core`, ...); numărată pe rânduri, „491 de vulnerabilități" ar fi
        umflat de cinci ori ce se repară de fapt;
      * CE rulează față de ce e instalat, ca să nu fie de crezut pe cuvânt;
      * ce se ÎNTÂMPLĂ după: scanarea nocturnă le închide singură;
      * ce NU poate verifica Sentinel: nucleul implicit la pornire. `/boot/grub2`
        e doar pentru root. Dacă implicitul ar fi un nucleu VECHI, repornirea n-ar
        aplica nimic — de aceea comanda de verificare e în mesaj, nu presupusă.
    """
    from sentinel.scan import fix_state

    rank = {s: i for i, s in enumerate(_SEV_ORDER)}

    def _worse(a: str, b: str) -> str:
        return a if rank.get(a, len(rank)) <= rank.get(b, len(rank)) else b

    by_cve: dict[str, str] = {}
    kev_cves: set[str] = set()
    packages: set[str] = set()
    for f in items:
        cve = str(f.get("cve") or f"id-{f.get('id')}")
        sev = str(f.get("severity") or "medium")
        by_cve[cve] = _worse(by_cve[cve], sev) if cve in by_cve else sev
        if f.get("kev"):
            kev_cves.add(cve)
        if f.get("package"):
            packages.add(str(f["package"]))

    newest = fix_state.newest([str(f["installed"]) for f in items
                               if f.get("installed")])
    sev_counts = [f"{sum(1 for v in by_cve.values() if v == s)} {_SEV_RO[s]}"
                  for s in _SEV_ORDER if any(v == s for v in by_cve.values())]

    pkgs = sorted(packages)
    pkg_txt = ", ".join(f"<code>{_esc(p)}</code>" for p in pkgs[:MAX_PACKAGES_LISTED])
    if len(pkgs) > MAX_PACKAGES_LISTED:
        pkg_txt += f" și încă {len(pkgs) - MAX_PACKAGES_LISTED}"

    on_disk = f"nucleul <code>{_esc(newest)}</code>" if newest else "un nucleu mai nou"
    running_txt = (f"<code>{_esc(running)}</code>" if running
                   else "un nucleu mai vechi")

    lines = [
        f"🔁 <b>{_esc(host)} — reparațiile sunt instalate, dar nu rulează încă</b>",
        "",
        f"{len(items)} constatări ({len(by_cve)} CVE-uri distincte, pachete: "
        f"{pkg_txt}) sunt reparate în {on_disk}, care e pe disc. Sistemul rulează "
        f"însă {running_txt}: reparațiile se aplică doar după o repornire.",
    ]
    if sev_counts:
        lines.append("CVE-uri pe severitate: " + " · ".join(sev_counts) + ".")
    if kev_cves:
        listed = sorted(kev_cves)[:MAX_KEV_LISTED]
        more = (f" și încă {len(kev_cves) - MAX_KEV_LISTED}"
                if len(kev_cves) > MAX_KEV_LISTED else "")
        lines.append(f"🔥 <b>{len(kev_cves)} se exploatează activ (KEV):</b> "
                     + ", ".join(f"<code>{_esc(c)}</code>" for c in listed) + more
                     + ". Gazda rămâne expusă la ele până la repornire.")
    lines += [
        "",
        ("<b>Ce e de făcut:</b> repornești serverul cât mai curând — există CVE-uri "
         "exploatate activ printre ele. Sentinel nu repornește nimic."
         if kev_cves else
         "<b>Ce e de făcut:</b> repornești serverul când îți convine. Sentinel "
         "nu repornește nimic."),
        "Înainte, verifică ce nucleu pornește implicit — Sentinel nu poate citi "
        "<code>/boot</code>: <code>sudo grubby --default-kernel</code> trebuie să "
        + (f"arate <code>{_esc(newest)}</code>." if newest else "arate nucleul nou."),
        "",
        "Rămân deschise în panou (și numărate ca KEV) până la repornire: gazda "
        "chiar e expusă cât timp rulează nucleul vechi.",
        "Un plan de patch pentru ele nu are ce instala (<code>dnf</code> "
        "nu mai are nimic de actualizat) și nu schimbă nimic — de aceea Sentinel nu "
        "redactează niciunul. După repornire, "
        "scanarea nocturnă le închide singură.",
    ]
    return "\n".join(lines)


def build_pending_reboot_reminder(items: Sequence[dict[str, Any]], *, host: str,
                                  running: str | None,
                                  today: Any = None) -> str:
    """Reamintirea zilnică: CVE-uri exploatate activ, reparate pe disc, încă
    nerulate. Funcție PURĂ.

    De ce există, deși mesajul integral pleacă o dată. Constatările astea rămân
    `open` și numărate (decizia operatorului din 29 septembrie 2026), dar
    planificatorul nu mai redactează pentru ele niciun plan — deci nu mai există
    nici refuzul, nici alarma de la patru ore care, urât, îl ținea treaz.
    Fără o reamintire, un KEV în așteptare ar fi `open`, numărat, fără plan și
    fără nicio veste: adică exact tăcerea pe care mecanismul întreg a fost
    scris s-o evite. Un mesaj trimis o singură dată se poate rata; unul pe zi,
    doar pentru ce se exploatează activ și doar cât timp așteaptă, se citește.

    Scurt dinadins: e singurul lucru repetat, deci singurul pe care operatorul
    ar ajunge să-l oprească. Nu enumeră necritice și nu repetă instrucțiunile
    întregi.
    """
    import datetime as _dt

    kev = {}
    for f in items:
        cve = str(f.get("cve") or f"id-{f.get('id')}")
        kev.setdefault(cve, f)
    if today is None:
        today = _dt.datetime.now(_dt.timezone.utc).date()

    days: list[int] = []
    for f in items:
        try:
            days.append((today - _dt.date.fromisoformat(str(f.get("since")))).days)
        except (TypeError, ValueError):
            pass
    waited = (f" de {max(days)} zile" if days and max(days) >= 1 else "")

    listed = sorted(kev)[:MAX_KEV_LISTED]
    more = f" și încă {len(kev) - MAX_KEV_LISTED}" if len(kev) > MAX_KEV_LISTED else ""
    running_txt = f"<code>{_esc(running)}</code>" if running else "nucleul vechi"
    newest = None
    try:
        from sentinel.scan import fix_state
        newest = fix_state.newest([str(f["installed"]) for f in items
                                   if f.get("installed")])
    except Exception:  # noqa: BLE001 - reamintirea nu depinde de comparația de versiuni
        newest = None

    lines = [
        f"🔥 <b>{_esc(host)} — {len(kev)} "
        f"{'vulnerabilitate exploatată' if len(kev) == 1 else 'vulnerabilități exploatate'}"
        f" activ așteaptă o repornire{waited}</b>",
        ", ".join(f"<code>{_esc(c)}</code>" for c in listed) + more + ".",
        f"Reparația e instalată"
        + (f" (<code>{_esc(newest)}</code>)" if newest else "")
        + f", dar sistemul rulează încă {running_txt}: gazda e expusă până la "
        "repornire. Sentinel nu repornește nimic.",
        "Verifică înainte nucleul implicit: <code>sudo grubby --default-kernel</code>.",
        "<i>Mesajul se repetă la fiecare scanare cât timp așteaptă; repornirea îl "
        "oprește.</i>",
    ]
    return "\n".join(lines)


async def announce_pending_reboot(cfg: Any, items: Iterable[dict[str, Any]], *,
                                  running: str | None) -> int:
    """Trimite mesajul despre reparațiile în așteptarea repornirii.

    Se cheamă o singură dată pe trecere, cu constatările care au TRECUT în starea
    asta chiar acum — nu cu tot ce e în ea. Un mesaj repetat la fiecare scanare
    despre aceleași 491 de rânduri e un canal pe care operatorul îl oprește.

    Aceleași reguli ca `announce`: comutatorul `scan.announce_new`, zero e un
    răspuns valid, livrarea numărată per chat. Dacă mesajul nu ajunge, starea
    rămâne (e un fapt despre gazdă, nu despre Telegram), iar operatorul o mai
    găsește în răspunsul lui `/planifica` și `/vuln`; eșecul e în jurnal.
    """
    rows = list(items)
    if not rows:
        return 0
    if not getattr(cfg.scan, "announce_new", True):
        return 0
    return await _deliver(
        cfg, lambda host: build_pending_reboot_message(rows, host=host, running=running),
        label="despre reparații în așteptarea repornirii", count=len(rows))


async def announce_pending_reboot_reminder(cfg: Any, items: Iterable[dict[str, Any]], *,
                                           running: str | None) -> int:
    """Trimite reamintirea zilnică pentru KEV-urile aflate în așteptarea repornirii.

    Se cheamă cu rândurile KEV care așteaptă de la o scanare anterioară (cele
    intrate acum sunt în mesajul integral). Aceleași reguli ca `announce`:
    comutatorul `scan.announce_new` o oprește și pe ea, zero e un răspuns valid,
    livrarea se numără per chat.
    """
    rows = [dict(r) for r in items if r.get("kev")]
    if not rows:
        return 0
    if not getattr(cfg.scan, "announce_new", True):
        return 0
    return await _deliver(
        cfg, lambda host: build_pending_reboot_reminder(rows, host=host, running=running),
        label="de reamintire a KEV în așteptarea repornirii", count=len(rows))
