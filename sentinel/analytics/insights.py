"""Derive actionable statements from the data — the interpretation layer.

Every insight is a deterministic rule over the tables: it fires only when its
own evidence threshold is met, it carries the numbers it was derived from, and
it says what to DO about it. No model call, so the dashboard is instant and
reproducible.

Three design rules, learned from dashboards that get ignored:

  1. **An insight must be actionable or it is noise.** "1,200 events today" is a
     number, not an insight. "root was targeted 919 times from 73 addresses —
     disable PermitRootLogin" is one.
  2. **Absence of data is itself a finding.** A collector that silently stopped
     looks exactly like a quiet week. `_gap_insights` exists because that
     actually happened here: SSH ingestion died for three days and every screen
     kept showing a reassuring zero.
  3. **Never claim more than the data supports.** If GeoIP is missing, say
     attribution is unavailable rather than rendering an empty column.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.analytics import aggregate
from sentinel.db.engine import Database

# Severity of the insight itself, not of the underlying events.
LEVELS = ("critical", "warning", "info", "good")


@dataclass
class Insight:
    level: str
    title: str
    detail: str
    action: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


# Applications commonly probed by mass scanners. Seeing sustained traffic for one
# of these tells you which campaign you are caught in — and if the app is not
# installed, that the traffic is pure background noise you can safely ignore.
_APP_PROBES = {
    "glpi": ("GLPI", "/glpi"),
    "wp-content": ("WordPress", "/wp-content"),
    "wp-admin": ("WordPress", "/wp-admin"),
    "phpmyadmin": ("phpMyAdmin", "/phpmyadmin"),
    "xmlrpc.php": ("WordPress XML-RPC", "/xmlrpc.php"),
    ".env": ("fișiere .env expuse", "/.env"),
    ".git": ("depozite .git expuse", "/.git"),
    "boaform": ("routere/CPE", "/boaform"),
    "solr": ("Apache Solr", "/solr"),
}


async def collect(db: Database) -> list[Insight]:
    """Run every rule. One failing rule must not blank the page, so each is
    isolated — a dashboard that renders nothing is worse than one missing a card."""
    out: list[Insight] = []
    for rule in (_gap_insights, _multivector_insights, _ssh_target_insights,
                 _probe_campaign_insights, _blocklist_drift_insight,
                 _incident_flood_insight, _vuln_insight, _trend_insight,
                 _enrichment_insight, _ai_disagreement_insight,
                 _privilege_insight, _concentrated_asn_insight,
                 _exposure_crossing_insight, _campaign_insight):
        try:
            out.extend(await rule(db))
        except Exception:  # noqa: BLE001 - one bad rule must not empty the page
            continue
    order = {lvl: i for i, lvl in enumerate(LEVELS)}
    out.sort(key=lambda i: order.get(i.level, 99))
    return out


# --- 1. silent collectors --------------------------------------------------
#: Cea mai scurtă tăcere pe care regula de mai jos o numește defect, în ore.
#: Inventarul de surse are voie să fie mai vechi de atât? Nu: o sursă putea să
#: apară și să amuțească în intervalul ăla fără să intre vreodată în inventar,
#: iar regula ar raporta „nimic tăcut" despre o listă din care lipsește exact
#: cine tace. Pragul de aici nu e ales, e cel mai mic prag pe care regula îl
#: folosește mai jos — dacă ăla se mișcă, se mișcă și ăsta.
_TACERE_MINIMA_H = 6

#: Sursele care scriu un rând pe unitate de trafic — o conexiune, o cerere. Pe
#: o gazdă expusă traficul nu se oprește, deci câteva ore de tăcere chiar
#: înseamnă că s-a rupt ceva la colectare; se judecă cu pragul cel mai scurt de
#: mai sus.
#:
#: Măsurat pe gazdă pe 14 zile de date, cel mai mare gol: `nginx` 31m46s,
#: `sshd` 18m45s. Pragul de șase ore lasă peste zece ori marja aia.
#:
#: `suricata` A FOST aici și nu mai e. Rândurile ei nu vin din trafic, ci din
#: potriviri de semnătură: în aceleași 14 zile a avut un gol de 6h42m59s, unul
#: peste 3h și nouă peste o oră, în timp ce `eve.json` creștea cu ~333 MB/zi —
#: cititorul lucra, doar că nimic nu depășea un prag. La șase ore, panoul ar fi
#: strigat „sursa a amuțit" o dată la două săptămâni despre un colector
#: sănătos, adică fix falsul pozitiv scos din selfcheck pe 28 august 2026,
#: mutat pe celălalt ecran. Vezi `_TACERE_ALTE_SURSE_H`, unde a ajuns.
_SURSE_CONTINUE = frozenset({"nginx", "sshd"})

#: Pragul pentru sursele care nu sunt nici continue, nici acționate de om —
#: azi, `suricata`, `auditd` și ce mai apare în inventar.
#:
#: Pentru `suricata` e o marjă de ~10× peste cel mai mare gol observat în 14
#: zile (6h42m59s) — aceeași marjă pe care pragul de șase ore o are față de
#: `nginx` și `sshd`. Ales mai strâns n-are sens: golul de șase ore și trei
#: sferturi s-a întâmplat o dată, deci un prag pus la 12 sau la 24 de ore ar
#: aștepta doar săptămâna mai liniștită ca să dea aceeași alarmă falsă.
#:
#: De ce `suricata` nu stă la `_SURSE_ACTIONATE_DE_OM`, deși amândouă tac din
#: motive normale: tăcerea lui `su` nu se poate măsura DELOC — nu există nicio
#: cantitate din care să afli dacă cineva ar fi trebuit să tasteze ceva.
#: Tăcerea lui `suricata` se poate: golurile ei au o distribuție, iar 6h43m e
#: coada ei observată. Un suricata care chiar moare trebuie să se vadă, doar că
#: pe scara zecilor de ore, nu a orelor.
#:
#: Și, mai important: pragul ăsta e o PLASĂ LARGĂ peste una fină care există
#: deja în altă parte. `selfcheck/checks.py` judecă `suricata` pe offsetul
#: cursorului cititorului (`CURSOR_BACKED_SOURCES`), adică pe întrebarea
#: corectă — „mai citește cititorul?" — și prinde oprirea în minute, nu în ore.
#: Panoul n-are cursorul și nu trebuie să capete unul: numără și interpretează,
#: nu măsoară mecanismul. Cine strânge pragul de aici crezând că e singura
#: apărare a lui `suricata` reintroduce alarma falsă fără să câștige nimic —
#: plasa fină a prins deja ce era de prins, cu o oră înainte.
_TACERE_ALTE_SURSE_H = 72

#: Sursele ale căror evenimente există DOAR când un om tastează ceva pe server.
#: Tăcerea lor nu e dovadă de nimic: o gazdă pe care n-a lucrat nimeni o zi
#: produce zero evenimente `sudo`, iar aia e starea sănătoasă.
#:
#: Nu e lista „tot ce tace din motive normale". `suricata` tace și ea normal,
#: dar tăcerea ei se poate măsura, deci primește un prag larg
#: (`_TACERE_ALTE_SURSE_H`). Aici intră doar sursele a căror tăcere nu spune
#: NIMIC, fiindcă nu există nicio cantitate care s-o interpreteze.
#:
#: Regula de aici le judeca cu pragul de 72 de ore și i-a spus operatorului, în
#: `/dashboard`, „🟡 Sursa «su» a amuțit de 81 ore”, cu sfatul să verifice un
#: colector care funcționa. Aceeași greșeală o făcuse deja autoverificarea
#: (`HUMAN_DRIVEN` în selfcheck/checks.py), unde a costat un „SENTINEL NU
#: FUNCȚIONEAZĂ COMPLET" pe prima zi liniștită — iar o alarmă care sună într-un
#: weekend normal antrenează exact reflexul de a nu mai citi canalul.
#:
#: Ce NU le poate salva: un discriminator „vecinii scriu". Acela răspunde la
#: „gazda e liniștită sau colectorul e stricat?" comparând surse care numără
#: același fel de lucru. Nu răspunde la „a tastat cineva `sudo`?", fiindcă
#: nicio altă sursă nu măsoară asta.
#:
#: Ce le ține totuși supravegheate: `sshd`, `sudo` și `su` vin din ACELAȘI
#: cititor journald — un singur set de `_COMM`, o singură buclă, clasificate în
#: surse abia după aceea (`JOURNALD_COMMS` în services/ingest_service.py). Un
#: cititor stricat le oprește pe toate trei deodată, iar `sshd` e în
#: `_SURSE_CONTINUE` și pe o gazdă expusă nu tace niciodată. Deci rândul lui
#: `sshd` E dovada de viață pentru `sudo` și `su`, iar defectul se anunță o
#: dată, acolo unde e cauza, nu de trei ori.
#:
#: Ce rămâne neprins, spus în loc să fie ascuns: o regresie de parsare doar pe
#: `sudo` — o distribuție care schimbă formatul liniei, iar tiparul din
#: collectors/system.py nu mai potrivește — ar lăsa `sudo` gol la nesfârșit
#: lângă un `sshd` care curge. Aceeași gaură e descrisă și în selfcheck.
#:
#: Nu se importă `HUMAN_DRIVEN` din selfcheck/checks.py, deși e aceeași listă:
#: modulul ăla e diagnosticul gazdei, aduce cu el `yaml`, `subprocess` și
#: `CONFIG_PATH`, iar `insights.py` se încarcă la fiecare afișare a panoului.
#: Un import făcut doar ca să se scutească două nume ar lega pagina de
#: subsistemul de autoverificare pentru totdeauna. E același raționament ca la
#: `_PLAFON_COADA_ORE` din aggregate.py, care nu importă `_TACERE_MINIMA_H` de
#: aici: constantele stau local, iar faptul că cele două liste trebuie să fie
#: identice se verifică în testul care are voie să le vadă pe amândouă (vezi
#: tests/unit/test_insights.py). Dacă se despart, operatorul primește două
#: verdicte contrare despre aceeași sursă, pe două ecrane.
_SURSE_ACTIONATE_DE_OM = frozenset({"sudo", "su"})

#: De la cât timp merită SPUS, fără să fie defect, că o sursă acționată de om
#: n-a mai scris. Aceeași cifră ca `_TACERE_ALTE_SURSE_H`, din alt motiv: acolo
#: e pragul de la care tăcerea e o pană, aici doar cât e nevoie ca să nu apară
#: un card la fiecare încărcare a paginii. Se mișcă independent.
_TACERE_DE_MENTIONAT_H = 72

# Ridicată din funcție ca un test s-o poată RULA, nu doar citi — același motiv
# ca la `_FORTARE_SQL` mai jos.
#
# `last_activity_sql()` dă inventarul ȘI ultima activitate dintr-o singură
# trecere prin `event_rollup_1m`, cu o coadă din `raw_events` care pornește de
# la frontiera rollup-ului. Forma dinainte punea un `LATERAL` cu `max(ts)` per
# pereche peste 30 de zile de evenimente brute: măsurată pe gazdă, 4624 ms
# dintr-o pagină de 18,4 s — și încă o dată atâta în `aggregate.sources`, care
# punea aceeași întrebare pentru cardul de alături.
#
# Ce se schimbă în datele care ies, nu doar în viteză: `last_seen` nu mai poate
# fi NULL, fiindcă fiecare rând vine dintr-un `max` peste un rând care există.
# Vezi bucla de mai jos pentru ce se întâmplă cu întrebarea la care răspundea
# NULL-ul.
_GAP_SQL = f"""
    WITH activitate AS ({aggregate.last_activity_sql()})
    SELECT source, max(ultim) AS last_seen,
           EXTRACT(EPOCH FROM (now() - max(ultim))) / 3600 AS hours_silent
      FROM activitate
     GROUP BY 1
"""  # noqa: S608 - SQL din constante de modul, nu din date de la cineva


async def _gap_insights(db: Database) -> list[Insight]:
    """A source that stopped reporting. This is the most dangerous failure mode
    in the whole system: it is indistinguishable from "nothing happened" on
    every other screen, and it is exactly what happened when an OpenSSH upgrade
    renamed the process that logs authentication.

    Costul e dat de mărimea rollup-ului, nu de a evenimentelor brute: vezi
    `_GAP_SQL` mai sus și `aggregate.last_activity_sql`.

    Nu tot ce tace e defect. `sudo` și `su` scriu doar când un om tastează, deci
    despre ele se raportează CÂND au scris ultima dată, fără verdict — vezi
    `_SURSE_ACTIONATE_DE_OM`.
    """
    # Inventarul e ce face regula capabilă să vadă o sursă TĂCUTĂ: o sursă care
    # nu mai scrie nu apare în date, deci trebuie să știm dinainte că ar fi
    # trebuit să apară. Dacă inventarul lipsește sau e prea vechi, singurul
    # răspuns onest e „nu pot ști" — nu tăcere, și nici „totul e bine".
    lag_h = await db.fetchval(
        "SELECT EXTRACT(EPOCH FROM (now() - max(bucket))) / 3600 "
        "FROM event_rollup_1m")
    if lag_h is None or float(lag_h) > _TACERE_MINIMA_H:
        vechime = "gol" if lag_h is None else f"vechi de {float(lag_h):.0f} ore"
        return [Insight(
            level="warning",
            title="Nu se poate spune dacă vreo sursă a amuțit",
            detail=(f"Inventarul de surse vine din `event_rollup_1m`, care e "
                    f"{vechime}. O sursă care tace nu apare în date, deci fără "
                    f"un inventar proaspăt tăcerea ei arată identic cu "
                    f"inexistența ei. Verificarea NU spune că totul e bine."),
            action="systemctl status sentinel-maintenance.timer ; "
                   "journalctl -u sentinel-maintenance -n 50",
            evidence={"rollup_lag_ore": None if lag_h is None else round(float(lag_h), 1)},
        )]

    rows = await db.fetch(_GAP_SQL)
    out: list[Insight] = []
    for r in rows:
        sursa = r["source"]
        if r["last_seen"] is None or r["hours_silent"] is None:
            # Ramura asta a rămas fără intrarea ei din date: cu `_GAP_SQL`,
            # inventarul și ultima activitate vin din același `max`, deci o
            # sursă listată are întotdeauna un moment. Întrebarea la care
            # răspundea NULL-ul — „e în inventar, dar n-a scris nimic în
            # fereastră" — și-a găsit un răspuns mai bun: sursa iese acum cu
            # vârsta ei adevărată (rollup-ul ține 90 de zile, mai mult decât
            # retenția rândurilor brute) și cade în pragurile de mai jos, în loc
            # de un plafon inventat de 30 de zile.
            #
            # Ce se face aici e altceva. Dacă valoarea lipsește TOTUȘI, nu se
            # știe nimic despre sursa asta, iar `or 0` ar fi citit-o ca „văzută
            # acum" și ar fi tăcut — exact forma de minciună pe care regula
            # există ca s-o prevină. „Nu pot ști" și „e bine" sunt stări
            # diferite, și rămân diferite și când starea nu e explicabilă.
            out.append(Insight(
                level="warning",
                title=f"Nu se poate spune de când tace sursa „{sursa}”",
                detail=("Sursa apare în inventar, dar ultima ei activitate a ieșit "
                        "goală — ceea ce nu se poate întâmpla cât timp inventarul "
                        "și ultima activitate vin din același loc. Verificarea NU "
                        "spune că sursa e în regulă."),
                action=f"Verifică colectorul: journalctl -u sentinel-ingest | grep {sursa}",
                evidence={"sursa": sursa, "ore_tacere": None},
            ))
            continue
        hours = float(r["hours_silent"])
        ultim = f"{r['last_seen']:%d.%m %H:%M}"
        if sursa in _SURSE_ACTIONATE_DE_OM:
            # Raportată, niciodată alarmă: operatorul vede în continuare sursa
            # și când a scris ultima dată, dar tăcerea ei nu mai e defect.
            #
            # `info` înseamnă că nu ajunge în `/dashboard` pe Telegram, care
            # arată doar `critical` și `warning` (vezi telegram/views.py). Asta
            # e chiar ce se voia: canalul de alertare poartă defecte, iar aici
            # nu e niciunul. Pe pagina web cardul se vede întreg, iar sursa
            # rămâne oricum în tabelul „Surse de date", cu ultima ei activitate.
            if hours < _TACERE_DE_MENTIONAT_H:
                continue
            out.append(Insight(
                level="info",
                title=f"Sursa „{sursa}” tace de {hours:.0f} ore — normal",
                detail=(f"Ultimul eveniment: {ultim}. „{sursa}” scrie doar când "
                        f"cineva tastează comanda pe server, deci tăcerea ei nu "
                        f"spune nimic despre colector — o zi în care nu a lucrat "
                        f"nimeni arată exact așa. Că citirea funcționează se vede "
                        f"din „sshd”, care vine din același cititor journald și "
                        f"care, expus la internet, nu tace niciodată; dacă s-ar "
                        f"opri, ar apărea aici ca defect."),
                evidence={"sursa": sursa, "ore_tacere": round(hours, 1),
                          "actionata_de_om": True},
            ))
            continue
        threshold = _TACERE_MINIMA_H if sursa in _SURSE_CONTINUE else _TACERE_ALTE_SURSE_H
        if hours >= threshold:
            out.append(Insight(
                level="critical" if hours >= threshold * 4 else "warning",
                title=f"Sursa „{sursa}” a amuțit de {hours:.0f} ore",
                detail=(f"Ultimul eveniment: {ultim}. O sursă care "
                        f"tace arată identic cu „nu s-a întâmplat nimic” — dar înseamnă "
                        f"că nu mai vezi ce se întâmplă acolo."),
                action=f"Verifică colectorul: journalctl -u sentinel-ingest | grep {sursa}",
                evidence={"sursa": sursa, "ore_tacere": round(hours, 1)},
            ))
    return out


# --- 2. deliberate targeting ------------------------------------------------
async def _multivector_insights(db: Database) -> list[Insight]:
    """An address seen by several independent collectors is not drive-by
    scanning: it tried SSH, it hit the web server, and the IDS flagged it. That
    combination is the strongest cheap signal of a deliberate target."""
    rows = await db.fetch(
        """
        SELECT host(src_ip) AS ip, count(DISTINCT source) AS surse,
               string_agg(DISTINCT source, '+' ORDER BY source) AS care,
               count(*) AS ev
        FROM raw_events
        WHERE ts > now() - interval '48 hours' AND src_ip IS NOT NULL
          AND action IN ('auth_fail', 'alert', 'request')
        GROUP BY 1 HAVING count(DISTINCT source) >= 3
        ORDER BY ev DESC LIMIT 5
        """
    )
    if not rows:
        return []
    ips = [r["ip"] for r in rows]
    return [Insight(
        level="warning",
        title=f"{len(ips)} adrese te atacă pe mai multe fronturi simultan",
        detail=("Aceste adrese apar în 3 surse independente (SSH, web și IDS) în "
                "ultimele 48h. Un scanner de masă atinge o singură suprafață; "
                "cine încearcă trei te-a ales pe tine."),
        action=f"Blochează-le din Telegram: /block {ips[0]} 24h",
        evidence={"adrese": ips, "detalii": [f"{r['ip']} ({r['care']}, {r['ev']} ev)" for r in rows]},
    )]


# --- 3. what they try on SSH ------------------------------------------------
async def _ssh_target_insights(db: Database) -> list[Insight]:
    rows = await db.fetch(
        """
        SELECT username, sum(n)::bigint AS n, count(ip) AS ips
        FROM (SELECT username, host(src_ip) AS ip, count(*) AS n
                FROM raw_events
               WHERE source = 'sshd' AND action = 'auth_fail'
                 AND username IS NOT NULL
                 AND ts > now() - interval '7 days'
               GROUP BY 1, 2) pereche
        GROUP BY 1 ORDER BY n DESC LIMIT 5
        """
    )
    if not rows:
        return []
    top = rows[0]
    out = [Insight(
        level="info",
        title=f"Conturile țintite: „{top['username']}” conduce cu {top['n']} încercări",
        detail=("Cine încearcă și ce nume. Sunt conturi standard ghicite automat, "
                "nu nume aflate despre tine — semn de scanare industrială, nu de "
                "recunoaștere țintită."),
        evidence={"top": [f"{r['username']} — {r['n']} încercări / {r['ips']} adrese" for r in rows]},
    )]
    if top["username"] == "root" and top["n"] >= 100:
        out.append(Insight(
            level="warning",
            title=f"root e ținta #1 — {top['n']} încercări de la {top['ips']} adrese",
            detail=("Atât timp cât autentificarea SSH cu parolă pentru root este "
                    "posibilă, fiecare dintre aceste încercări are o șansă. Cu "
                    "`PermitRootLogin no` toate devin imposibile din start."),
            action="Verifică: grep PermitRootLogin /etc/ssh/sshd_config",
            evidence={"incercari": top["n"], "adrese": top["ips"]},
        ))
    return out


# --- 4. which campaign are we in -------------------------------------------
async def _probe_campaign_insights(db: Database) -> list[Insight]:
    rows = await db.fetch(
        """
        SELECT http_path, sum(n)::bigint AS n, count(ip) AS ips
        FROM (SELECT http_path, host(src_ip) AS ip, count(*) AS n
                FROM raw_events
               WHERE source = 'nginx' AND http_status = 404
                 AND http_path IS NOT NULL
                 AND ts > now() - interval '7 days'
               GROUP BY 1, 2) pereche
        GROUP BY 1 ORDER BY n DESC LIMIT 40
        """
    )
    # `retired_at IS NULL` = urmărit; NULL e starea în care se nasc rândurile,
    # iar un moment scris acolo înseamnă „scos din inventory.yaml atunci" (vezi
    # migrația 0032 și `scan/inventory.py:sync`). Interogarea de aici e SQL crud,
    # deci NU moștenește filtrul din `assets_repo.list_all` — trebuie scris.
    #
    # Fără el, `webmin` — dezinstalat de pe gazdă în august, deci retras la
    # următoarea sincronizare — ar continua să treacă drept instalat, iar o
    # sondă după `/webmin/` ar fi urcată la `warning` cu textul „**Rulezi
    # această aplicație**". Greșeala e în direcția care sperie degeaba: îl
    # trimite pe operator să verifice versiunea unui pachet pe care nu-l mai
    # are. Un activ retras își păstrează rândul fiindcă îi e referit istoricul,
    # nu fiindcă mai e instalat.
    installed = {r["name"].lower() for r in
                 await db.fetch("SELECT name FROM assets WHERE retired_at IS NULL")}
    hits: dict[str, dict[str, int]] = {}
    for r in rows:
        path = (r["http_path"] or "").lower()
        for needle, (label, _) in _APP_PROBES.items():
            if needle in path:
                h = hits.setdefault(label, {"n": 0, "ips": 0})
                h["n"] += int(r["n"])
                h["ips"] = max(h["ips"], int(r["ips"]))
    out: list[Insight] = []
    for label, h in sorted(hits.items(), key=lambda kv: -kv[1]["n"])[:3]:
        # If the probed application is not among this host's assets, the whole
        # campaign is noise — worth saying explicitly so it is not chased.
        runs_it = any(label.split()[0].lower() in a for a in installed)
        out.append(Insight(
            level="warning" if runs_it else "info",
            title=f"Campanie activă împotriva {label}: {h['n']} sondări",
            detail=(f"De la {h['ips']} adrese în 7 zile. "
                    + ("**Rulezi această aplicație** — sondările sunt relevante și "
                       "merită verificată versiunea."
                       if runs_it else
                       "Nu rulezi această aplicație, deci nu te poate atinge — e "
                       "zgomot de fond, util doar ca să știi în ce val ești.")),
            action="Verifică versiunea și patch-urile aplicației" if runs_it else None,
            evidence={"sondari": h["n"], "adrese": h["ips"], "instalat": runs_it},
        ))
    return out


# --- 5. does the firewall match the database -------------------------------
async def _blocklist_drift_insight(db: Database) -> list[Insight]:
    """The database says an address is blocked; the kernel is the truth. They
    drift after a reboot, because blocks deliberately do not persist — which is
    an anti-lockout feature, but leaves the UI claiming protection that is gone."""
    db_active = int(await db.fetchval(
        "SELECT count(*) FROM blocklist WHERE active") or 0)
    if db_active == 0:
        return []
    try:
        from sentinel.respond import actions
        live = await actions.live_count()
    except Exception:  # noqa: BLE001 - executor unreachable
        return []
    if live < 0 or live >= db_active:
        return []
    return [Insight(
        level="warning",
        title=f"{db_active - live} blocări figurează în evidență dar nu mai sunt în firewall",
        detail=(f"Evidența are {db_active} adrese blocate activ, dar setul nftables "
                f"conține {live}. Blocările nu supraviețuiesc intenționat unui reboot "
                "(este plasa anti-lockout), deci după repornire evidența rămâne în urmă."),
        action="Reblochează-le dacă mai sunt relevante, sau marchează-le ca ridicate",
        evidence={"in_evidenta": db_active, "in_kernel": live},
    )]


# --- 6. is one rule burying everything else --------------------------------
async def _incident_flood_insight(db: Database) -> list[Insight]:
    rows = await db.fetch(
        """
        SELECT split_part(fingerprint, ':', 1) AS regula, count(*) AS n
        FROM incidents WHERE status = 'open' GROUP BY 1 ORDER BY n DESC
        """
    )
    total = sum(int(r["n"]) for r in rows)
    if total < 50 or not rows:
        return []
    top = rows[0]
    share = int(top["n"]) / total
    if share < 0.6:
        return []
    return [Insight(
        level="warning",
        title=f"{share:.0%} din incidentele deschise vin dintr-o singură regulă",
        detail=(f"„{top['regula']}” a produs {top['n']} din {total} incidente deschise. "
                "Când o regulă domină astfel, restul semnalelor devin invizibile — "
                "nu pentru că lipsesc, ci pentru că nu le mai vezi în listă."),
        action="Ridică pragul regulii sau rezolvă în masă incidentele vechi",
        evidence={"regula": top["regula"], "din_regula": int(top["n"]), "total": total},
    )]


# --- 7. patch posture -------------------------------------------------------
async def _vuln_insight(db: Database) -> list[Insight]:
    row = await db.fetchrow(
        """
        SELECT count(*) FILTER (WHERE status = 'open') AS deschise,
               count(*) FILTER (WHERE status = 'open' AND kev) AS kev,
               count(*) FILTER (WHERE status = 'resolved') AS rezolvate
        FROM findings
        """
    )
    if row is None:
        return []
    deschise, kev, rezolvate = int(row["deschise"] or 0), int(row["kev"] or 0), int(row["rezolvate"] or 0)
    if kev:
        return [Insight(
            level="critical",
            title=f"{kev} vulnerabilități exploatate ACTIV în acest moment",
            detail=("CISA le listează ca exploatate în sălbăticie chiar acum (KEV). "
                    "Nu e o probabilitate teoretică — există exploit-uri în circulație."),
            action="dnf update --security -y, apoi reboot dacă e kernel",
            evidence={"kev": kev, "total_deschise": deschise},
        )]
    if deschise:
        return [Insight(
            level="warning",
            title=f"{deschise} vulnerabilități deschise, niciuna exploatată activ",
            detail="Nimic pe lista KEV, deci nu e urgent — dar rămân de reparat.",
            action="Programează un dnf update --security",
            evidence={"deschise": deschise},
        )]
    if rezolvate:
        return [Insight(
            level="good",
            title="Zero vulnerabilități de securitate deschise",
            detail=(f"{rezolvate} au fost reparate și confirmate de scanarea următoare. "
                    "Sistemul de operare e la zi."),
            evidence={"rezolvate": rezolvate},
        )]
    return []


# --- 8. is it getting worse -------------------------------------------------
async def _trend_insight(db: Database) -> list[Insight]:
    row = await db.fetchrow(
        """
        SELECT
          count(*) FILTER (WHERE ts > now() - interval '24 hours') AS azi,
          count(*) FILTER (WHERE ts > now() - interval '48 hours'
                             AND ts <= now() - interval '24 hours') AS ieri
        FROM raw_events
        WHERE ts > now() - interval '48 hours'
          AND action IN ('auth_fail', 'alert')
        """
    )
    azi, ieri = int(row["azi"] or 0), int(row["ieri"] or 0)
    if ieri < 20 or azi < 20:
        return []
    ratio = azi / ieri
    if ratio >= 10:
        # An order-of-magnitude jump almost always means the comparison window
        # was broken (a collector down, rows pruned), not a real surge. Saying
        # "×37" would send someone hunting a campaign that does not exist.
        return [Insight(
            level="info",
            title="Comparația cu ziua precedentă nu este de încredere",
            detail=(f"{azi} evenimente în 24h față de doar {ieri} anterior. O "
                    "diferență de acest ordin înseamnă de obicei că fereastra de "
                    "referință e incompletă — un colector oprit sau date curățate — "
                    "nu o creștere reală. Se corectează singură în 24h."),
            evidence={"azi": azi, "ieri": ieri},
        )]
    if ratio >= 2:
        return [Insight(
            level="warning",
            title=f"Activitatea ostilă s-a dublat față de ieri (×{ratio:.1f})",
            detail=f"{azi} evenimente în 24h, față de {ieri} în ziua precedentă.",
            action="Verifică dacă e o campanie nouă în lista de atacatori",
            evidence={"azi": azi, "ieri": ieri},
        )]
    if ratio <= 0.5:
        return [Insight(
            level="good",
            title=f"Activitatea ostilă a scăzut la jumătate față de ieri",
            detail=f"{azi} evenimente în 24h, față de {ieri} anterior.",
            evidence={"azi": azi, "ieri": ieri},
        )]
    return []


# --- 9. how good is the attribution ----------------------------------------
async def _enrichment_insight(db: Database) -> list[Insight]:
    row = await db.fetchrow(
        """
        SELECT count(*) AS tot,
               count(*) FILTER (WHERE geo_country IS NOT NULL) AS cu_tara
        FROM raw_events
        WHERE ts > now() - interval '24 hours' AND src_ip IS NOT NULL
        """
    )
    tot = int(row["tot"] or 0)
    if tot < 100:
        return []
    if int(row["cu_tara"] or 0) == 0:
        return [Insight(
            level="info",
            title="Atribuirea geografică lipsește — nu știi de unde vin atacurile",
            detail=("Nicio adresă din ultimele 24h nu are țară sau ASN. Bazele "
                    "geo nu sunt instalate, deci vezi adrese, dar nu poți grupa "
                    "pe țară, operator sau campanie."),
            action="Rulează: sudo /opt/sentinel/bin/geoip-refresh.sh",
            evidence={"evenimente_fara_atribuire": tot},
        )]
    return []


# --- 10. where model and rules disagree ------------------------------------
async def _ai_disagreement_insight(db: Database) -> list[Insight]:
    rows = await db.fetch(
        """
        SELECT severity, ai_severity, count(*) AS n
        FROM incidents WHERE ai_severity IS NOT NULL GROUP BY 1, 2
        """
    )
    if not rows:
        return []
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    total = sum(int(r["n"]) for r in rows)
    downgrades = sum(int(r["n"]) for r in rows
                     if rank.get(r["ai_severity"], 9) < rank.get(r["severity"], 0))
    if total < 5 or downgrades / total < 0.3:
        return []
    return [Insight(
        level="info",
        title=f"Analiza AI a coborât severitatea la {downgrades} din {total} incidente",
        detail=("Modelul consideră că regulile exagerează. Verdictul determinist "
                "rămâne în vigoare — AI-ul comentează, nu suprascrie — dar dacă "
                "are dreptate constant, pragurile regulilor merită relaxate."),
        action="Compară câteva verdicte pe pagina de incident",
        evidence={"coborate": downgrades, "total_analizate": total},
    )]


# --- 11. post-compromise activity ------------------------------------------
async def _privilege_insight(db: Database) -> list[Insight]:
    row = await db.fetchrow(
        """
        SELECT count(*) FILTER (WHERE action = 'privilege_use') AS folosiri,
               count(*) FILTER (WHERE action = 'auth_fail') AS esecuri,
               count(DISTINCT username) FILTER (WHERE action = 'privilege_use') AS useri
        FROM raw_events
        WHERE source IN ('sudo', 'su') AND ts > now() - interval '24 hours'
        """
    )
    esecuri = int(row["esecuri"] or 0)
    if esecuri >= 5:
        return [Insight(
            level="critical",
            title=f"{esecuri} escaladări de privilegii EȘUATE în 24h",
            detail=("Cineva autentificat pe acest server încearcă să obțină root și "
                    "nu reușește. Asta e activitate post-compromitere: atacatorul "
                    "e deja înăuntru, pe un cont."),
            action="Verifică imediat ce conturi și de unde: /events?source=sudo",
            evidence={"esecuri": esecuri},
        )]
    return []


# --- 12. concentrated attacker infrastructure -------------------------------
async def _exposure_crossing_insight(db: Database) -> list[Insight]:
    """Somebody is probing exactly the hole this host has open.

    Ranked above everything else on the page when it fires, and it should be:
    the other rules describe activity, this one describes activity aimed at a
    specific unpatched thing on a specific machine. That is the difference
    between being scanned and being targeted.
    """
    from sentinel.predict import exposure

    rows = await exposure.recent(db, hours=24, limit=5)
    if not rows:
        return []

    kev = [r for r in rows if r.get("kev")]
    lead = rows[0]
    cve = lead.get("cve") or "vulnerabilitatea"
    actors = len({r["actor_key"] for r in rows})

    return [Insight(
        level="critical" if kev else "warning",
        title=(f"{actors} adres{'e' if actors > 1 else 'ă'} sondează exact ce nu e "
               f"patch-uit aici"),
        detail=(f"{lead['actor_key']} a cerut o cale care corespunde cu {cve} "
                f"({lead.get('package') or 'necunoscut'}), deschisă pe "
                f"{lead.get('asset_name') or 'această gazdă'}"
                + (" — și e în lista CISA de exploatate activ." if kev else ".")
                + " O scanare de masă atinge tot; asta atinge fix gaura ta."),
        action=(f"Patch acum: /vuln pentru detalii, sau blochează sursa: "
                f"/block {lead['actor_key']} 24h"),
        evidence={"potriviri": [
            f"{r['actor_key']} → {r.get('cve') or r.get('package')} "
            f"({r['match_reason']}, {float(r['confidence']):.0%})"
            for r in rows]},
    )]


async def _concentrated_asn_insight(db: Database) -> list[Insight]:
    """Many events from very few addresses inside one network operator. That is
    rented attack infrastructure, not a spread of compromised home machines —
    and it is the one case where blocking a range beats blocking hosts, because
    the next address will come from the same place."""
    rows = await db.fetch(
        """
        SELECT operator, sum(ev)::bigint AS ev, count(ip) AS ips
        FROM (SELECT geo_as_org AS operator, host(src_ip) AS ip, count(*) AS ev
                FROM raw_events
               WHERE ts > now() - interval '7 days' AND geo_as_org IS NOT NULL
                 AND action IN ('auth_fail','alert')
               GROUP BY 1, 2) pereche
        GROUP BY 1 HAVING sum(ev) >= 150 AND count(ip) <= 5
        ORDER BY ev DESC LIMIT 3
        """
    )
    if not rows:
        return []
    top = rows[0]
    names = ", ".join(f"{r['operator']} ({r['ev']} ev / {r['ips']} adrese)" for r in rows)
    return [Insight(
        level="warning",
        title=f"Infrastructură concentrată de atac: {top['operator']}",
        detail=(f"{top['ev']} evenimente ostile provin de la doar {top['ips']} adrese "
                "din aceeași rețea. Asta e infrastructură închiriată pentru atac, nu "
                "calculatoare compromise răspândite — iar următoarea adresă va veni "
                "din același loc."),
        action="Ia în calcul blocarea intervalului, nu doar a adreselor individuale",
        evidence={"detalii": [names]},
    )]


# --- 13. campaigns, not incidents -------------------------------------------
async def _campaign_insight(db: Database) -> list[Insight]:
    """968 de incidente deschise citite ca 14 campanii, grupate pe familia
    regulii — vezi `sentinel/db/repo/incident_campaigns.py`. Insight-ul ăsta spune câte
    fronturi sunt deschise ACUM și care e cel mai mare, în loc să lase
    judecata asta pe seama cuiva care derulează 968 de rânduri.

    „Cea mai mare" înseamnă cea cu cel mai mare `incident_count` — mărimea
    frontului, nu severitatea lui. `active_campaigns` întoarce rândurile
    ordonate după SEVERITATE (pentru cine se uită direct la listă, unde un
    `critical` trebuie să iasă primul), deci `rows[0]` de-acolo ar fi campania
    cea mai gravă, nu cea mai mare — iar un `critical` cu 2 incidente ar
    eclipsa o familie cu 500, sub titlul greșit. Rândul se alege explicit din
    tot setul, cu `max(..., key=...)`, tocmai ca sortarea listei sursă să nu
    decidă tăcut sensul cuvântului "mare" de-aici."""
    from sentinel.db.repo import incident_campaigns as camp_repo

    rows = await camp_repo.active_campaigns(db)
    if not rows:
        return []
    top = max(rows, key=lambda r: r["incident_count"])
    return [Insight(
        level="info",
        title=(f"{len(rows)} campanii active — cea mai mare: „{top['campaign_key']}” "
               f"({top['incident_count']} incidente, {top['actor_count']} actori)"),
        detail=("Incidentele sunt grupate pe familia regulii care le-a produs, nu "
                "citite unul câte unul. O campanie rămâne activă cât timp mai "
                "primește incidente noi din aceeași familie. „Cea mai mare” e "
                "campania cu cele mai multe incidente, nu neapărat cea mai severă."),
        evidence={"campanii": len(rows),
                  "cea_mai_mare": {"familie": top["campaign_key"],
                                   "incidente": top["incident_count"],
                                   "actori": top["actor_count"],
                                   "severitate": top["severity"]}},
    )]


# --- headline --------------------------------------------------------------
#: Câte eșecuri pe ACELAȘI cont, de la aceeași adresă, fac dintr-o reușită o
#: forțare care a mers — și nu pe cineva care și-a încurcat cheia.
#:
#: Ales pe datele gazdei (29 august 2026, 30 de zile): 3 354 de adrese au
#: produs 235 640 de eșecuri de autentificare, iar adresele care s-au
#: autentificat VREODATĂ cu succes sunt șase, toate ale operatorului. Cea mai
#: proastă zi a lor înseamnă 7 eșecuri într-o fereastră de 24h, deci pragul
#: trebuie să stea deasupra lui 7 ca o cheie greșită să nu mai fie numită
#: spargere. Douăzeci lasă aproape trei ori marja aia și rămâne mult sub ce
#: produce cine chiar forțează un cont de aici (~70 de eșecuri pe adresă în
#: medie, sutele pe adresele care insistă), deci nu golește regula.
#:
#: Ce se pierde cu el: o forțare „joasă și lentă” — sub 20 de încercări pe zi,
#: de la o adresă, pe contul în care intră — nu mai ridică titlul paginii.
#: Aceea rămâne în seama regulii de incident `intrusion.login_after_bruteforce`,
#: care se aprinde la 5 eșecuri în 30 de minute.
_FORTARE_ESECURI_MIN = 20


# The headline query, lifted out of the function so a test can RUN it and not
# merely read it: the aggregated shape below has to produce exactly the numbers
# the row-by-row shape it replaced produced, and the only honest way to show
# that is to put both over the same events.
#
# Two things make it cheap, and both of them matter on the one day the rule
# actually fires — an address that both forces and gets in:
#
#   * `publickey` is excluded in the `ok` CTE, not only in the Python loop
#     below. On this host every SSH success in a 24h window is a key, so
#     without it the database pays for the join on 100% of the rows Python
#     throws away on the next line. `IS DISTINCT FROM` rather than `<>` because
#     an UNKNOWN method must stay counted — same reasoning as the guard below,
#     said once in each layer.
#   * failures are aggregated BEFORE the join. The row-by-row shape was a
#     nested loop over successes × failures: measured on this host, 500
#     fabricated successes against one address' 1 525 real failures ran
#     2 745 ms row-by-row and 31 ms aggregated (29 Aug 2026). That matters
#     because `posture()` is NOT inside the per-rule `try/except` of
#     `collect()` (see `analytics/page.py` and `telegram/views.py`), so a
#     timeout here is a 500 on the dashboard, not a missing card.
#
#     Do not read the aggregation as the bound on this query — it is the
#     second line, and a weaker one than it looks. `esec` groups by
#     `(src_ip, username)`, and the reduction is only as good as the account
#     reuse: measured the same day, 7 240 failure rows collapsed to 1 344
#     groups (5.4x), and on one address that enumerates users it was 4x. An
#     attacker using a distinct account per attempt collapses nothing and the
#     join is back to O(successes × failures). What actually bounds this query
#     is the `publickey` filter above, which empties `ok` on a host where every
#     success is a key — `esec` is then never executed at all.
#
# `esecuri_cont` counts failures on the account that got in, `esecuri_ip` every
# failure from that address; grouping by `ok.id` keeps one output row per
# successful login, as before.
_FORTARE_SQL = """
    WITH ok AS (
        SELECT id, src_ip, username, raw->>'auth_method' AS metoda
          FROM raw_events
         WHERE source = 'sshd' AND action = 'auth_ok'
           AND src_ip IS NOT NULL
           AND ts > now() - interval '24 hours'
           AND raw->>'auth_method' IS DISTINCT FROM 'publickey'
    ),
    esec AS (
        SELECT src_ip, username, count(*) AS n
          FROM raw_events
         WHERE source = 'sshd' AND action = 'auth_fail'
           AND src_ip IS NOT NULL
           AND ts > now() - interval '24 hours'
           AND raw->>'auth_method' IS DISTINCT FROM 'publickey'
         GROUP BY 1, 2
    )
    SELECT host(ok.src_ip) AS ip, ok.username AS cont, ok.metoda AS metoda,
           coalesce(sum(f.n) FILTER (WHERE f.username = ok.username), 0)::bigint
               AS esecuri_cont,
           coalesce(sum(f.n), 0)::bigint AS esecuri_ip
      FROM ok
      LEFT JOIN esec f ON f.src_ip = ok.src_ip
     GROUP BY ok.id, ok.src_ip, ok.username, ok.metoda
     ORDER BY 4 DESC, 5 DESC
"""


async def posture(db: Database, insights: list[Insight]) -> dict[str, Any]:
    """One-line verdict for the top of the dashboard. The point is that someone
    can glance at it and know whether to keep reading."""
    crit = sum(1 for i in insights if i.level == "critical")
    warn = sum(1 for i in insights if i.level == "warning")
    row = await db.fetchrow(
        """
        SELECT count(DISTINCT host(src_ip)) AS atacatori, count(*) AS ev
        FROM raw_events
        WHERE ts > now() - interval '24 hours' AND src_ip IS NOT NULL
          AND action IN ('auth_fail', 'alert')
        """
    )
    # "Did a brute-force succeed?" — the version this replaced asked only
    # whether the address that logged in had ALSO failed here in the same 24h.
    # That is coexistence, not causality: on 28 August it read a deploy session
    # (three refused logins on `admin`, `deploy` and the operator's own account
    # within three seconds, then a key login as `sentinel-deploy` from the very
    # same address) as a break-in and told the
    # operator he was compromised. Over thirty days of this host's data the rule
    # was wrong every single time it fired — the six addresses that ever
    # authenticated successfully here are all the operator's.
    #
    # So the query asks for the evidence of forcing instead of the coincidence:
    #   * how many failures came from that address ON THE ACCOUNT THAT GOT IN —
    #     a brute-force that succeeds succeeds on the account it attacks, and
    #     failures on `admin` say nothing about a success on `sentinel-deploy`;
    #   * with what method the success happened — `publickey` is the one that
    #     cannot be reached by guessing.
    # `publickey` failures are left out of the count on purpose: an ssh-agent
    # holding several keys emits one refusal per key on a single connection,
    # which is how three "attacks" appeared within three seconds on 28 August.
    # Comparing against the `users` table would still be wrong: those are
    # dashboard accounts, not system accounts.
    rows = await db.fetch(_FORTARE_SQL)
    fortari: list[dict[str, Any]] = []
    for r in rows:
        # A key is not arrived at by guessing, so a `publickey` success is not a
        # forcing that worked. An UNKNOWN method is not read as safe: the sshd
        # parser leaves `auth_method` out of "Invalid user" lines, and "I cannot
        # tell" must not turn into "all clear".
        # `_FORTARE_SQL` already drops these rows; this is not leftover
        # duplication. There it buys the query its speed, here it decides the
        # verdict — so whoever edits the CTE next cannot delete the defence by
        # accident, only the optimisation.
        if r["metoda"] == "publickey":
            continue
        cont = r["cont"]
        # Without a username on the success there is no account to match, so the
        # address' own failures stand in — weaker evidence, but staying silent
        # here would be the same lie the old rule told, pointed the other way.
        esecuri = int((r["esecuri_ip"] if cont is None else r["esecuri_cont"]) or 0)
        if esecuri >= _FORTARE_ESECURI_MIN:
            fortari.append({"ip": r["ip"], "cont": cont, "esecuri": esecuri})
    breaches = len(fortari)

    # This outranks everything else on the page, and it says what was SEEN — a
    # success on an account the same address had been failing on, and how many
    # times — not the conclusion "an attacker got in". That conclusion is the
    # operator's to draw; drawing it for him is what turned a deploy into a
    # 3 a.m. scare.
    if fortari:
        top = fortari[0]
        level = "critical"
        if top["cont"] is None:
            verdict = (f"Reușită SSH de la o adresă cu {top['esecuri']} eșecuri "
                       f"în aceleași 24h; contul nu a putut fi citit — "
                       f"verifică ACUM")
        else:
            # The account name is copied verbatim out of the sshd log, so the
            # attacker picks it (see collectors/sshd.py). Escaping is done by
            # the templates and by `views.esc`; the length and the control
            # characters are nobody's job but this one's.
            cont = "".join(c for c in top["cont"] if c.isprintable())[:48]
            verdict = (f"Reușită SSH pe „{cont}” de la o adresă cu "
                       f"{top['esecuri']} eșecuri pe același cont în 24h — "
                       f"verifică ACUM")
    elif crit:
        level, verdict = "critical", "Necesită atenție acum"
    elif warn:
        level, verdict = "warning", "Sub atac constant, apărarea ține"
    else:
        level, verdict = "good", "Nimic de semnalat"
    return {
        "level": level,
        "verdict": verdict,
        "atacatori": int(row["atacatori"] or 0),
        "evenimente": int(row["ev"] or 0),
        "critice": crit,
        "avertismente": warn,
        "intruziuni": breaches,
    }
