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
                 _exposure_crossing_insight):
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


async def _gap_insights(db: Database) -> list[Insight]:
    """A source that stopped reporting. This is the most dangerous failure mode
    in the whole system: it is indistinguishable from "nothing happened" on
    every other screen, and it is exactly what happened when an OpenSSH upgrade
    renamed the process that logs authentication.

    Costul e dat de numărul de perechi (sursă, acțiune), nu de fereastră: vezi
    `aggregate._INVENTAR_SQL`. Varianta dinainte grupa 30 de zile de
    `raw_events` ca să scoată șase rânduri.
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

    rows = await db.fetch(
        f"""
        WITH inventar AS ({aggregate._INVENTAR_SQL})
        SELECT i.source, max(u.ultim) AS last_seen,
               EXTRACT(EPOCH FROM (now() - max(u.ultim))) / 3600 AS hours_silent
          FROM inventar i
          LEFT JOIN LATERAL (
              SELECT max(e.ts) AS ultim FROM raw_events e
               WHERE e.source = i.source AND e.action = i.action
                 AND e.ts > now() - interval '30 days') u ON true
         GROUP BY 1
        """  # noqa: S608 - _INVENTAR_SQL e o constantă de modul, nu date de la cineva
    )
    out: list[Insight] = []
    for r in rows:
        if r["last_seen"] is None:
            # În inventar, dar niciun rând în 30 de zile. `or 0` ar fi citit asta
            # ca „văzută acum" și ar fi tăcut exact despre colectorul cel mai
            # mort din listă.
            hours = 30 * 24.0
        else:
            hours = float(r["hours_silent"] or 0)
        # sudo/su are genuinely intermittent on a quiet host; the always-on
        # sources are the ones whose silence means a broken collector.
        threshold = _TACERE_MINIMA_H if r["source"] in ("nginx", "suricata", "sshd") else 72
        if hours >= threshold:
            ultim = (f"{r['last_seen']:%d.%m %H:%M}" if r["last_seen"] is not None
                     else "niciunul în 30 de zile")
            out.append(Insight(
                level="critical" if hours >= threshold * 4 else "warning",
                title=f"Sursa „{r['source']}” a amuțit de {hours:.0f} ore",
                detail=(f"Ultimul eveniment: {ultim}. O sursă care "
                        f"tace arată identic cu „nu s-a întâmplat nimic” — dar înseamnă "
                        f"că nu mai vezi ce se întâmplă acolo."),
                action=f"Verifică colectorul: journalctl -u sentinel-ingest | grep {r['source']}",
                evidence={"sursa": r["source"], "ore_tacere": round(hours, 1)},
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
    installed = {r["name"].lower() for r in await db.fetch("SELECT name FROM assets")}
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
#     nested loop over successes × failures; measured on this host, 500
#     successes against 13 191 failures took 20 s — past the 30 s
#     `statement_timeout_ms` — and `posture()` is NOT inside the per-rule
#     `try/except` of `collect()` (see `analytics/page.py` and
#     `telegram/views.py`), so a timeout here is a 500 on the dashboard.
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
