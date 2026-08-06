"""Reguli de post-compromitere: semnele că cineva a INTRAT.

Restul motorului de detecție se uită la tentative — brute-force, enumerare,
semnături de scanare. Sunt utile și sunt majoritatea zgomotului real de pe o
gazdă expusă, dar răspund la altă întrebare decât „a reușit cineva?".

Regulile de aici răspund la aceea. Se uită la ce face un atacator DUPĂ ce a
obținut execuție: își asigură revenirea, își crește privilegiile, își aduce
unelte, modifică ce servește serverul.

## Fără praguri de volum

O tentativă contează în rafală: opt autentificări eșuate nu înseamnă nimic, o
sută înseamnă atac. O compromitere reușită contează la prima apariție. O
singură cheie SSH scrisă în `/root/.ssh/authorized_keys` e tot ce trebuie ca
cineva să aibă acces permanent, iar a doua nu adaugă nimic la ce trebuie să
știi. De aceea regulile de aici pornesc de la prima observație.

Consecința e că fals-pozitivele dor. Un administrator care își adaugă legitim o
cheie declanșează aceeași alertă ca un atacator — și așa trebuie să fie. Un
sistem care tace la a doua cheie fiindcă prima a fost legitimă e un sistem care
poate fi antrenat de atacator. Calibrarea se face prin ferestre de mentenanță
și liste de excepții, nu prin praguri.

## De ce nu se blochează automat

Niciuna dintre regulile astea nu produce o adresă de blocat. Fapta e pe gazdă,
nu pe rețea: adresa care a scris cheia poate fi 127.0.0.1, sau poate lipsi cu
totul dacă atacatorul a intrat printr-un serviciu web. A bloca ceva pe baza lor
ar însemna, în cel mai bun caz, să blochezi un IP nevinovat; în cel mai rău, pe
al tău. Subiectul e gazda, iar decizia e a operatorului.
"""

from __future__ import annotations

import re
from typing import Any

from sentinel.db.engine import Database
from sentinel.detect.spec import DetectionSpec
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Fereastra de grupare. Zece minute înseamnă că o instalare de pachet care
# atinge patruzeci de fișiere produce o alertă, nu patruzeci.
WINDOW_MIN = 10

# Câte evenimente se citează într-o alertă înainte de a deveni ilizibilă.
MAX_QUOTED = 8

# Fereastra în care se caută eșecurile dinaintea unei autentificări reușite.
BRUTEFORCE_LOOKBACK_MIN = 30

# Câte eșecuri de la aceeași adresă fac reușita suspectă. Sub cinci, e un om
# care și-a greșit parola de câteva ori.
MIN_FAILS_BEFORE = 5

# Binarele care, executate de un utilizator obișnuit, sunt mai des unelte de
# atacator decât de administrator. `curl` și `wget` sunt pe listă cu jumătate de
# gură — le folosește toată lumea — dar sub un utilizator de aplicație web care
# nu a rulat niciodată nimic, sunt exact tiparul de descărcare a etapei a doua.
TOOL_WEIGHT = {
    "socat": "critical", "ncat": "critical", "nc": "critical",
    "curl": "high", "wget": "high",
}


def _fmt_paths(paths: list[str | None]) -> str:
    seen = [p for p in paths if p][:MAX_QUOTED]
    return ", ".join(f"`{p}`" for p in seen) or "—"


async def _grouped(db: Database, cursor: int, actions: tuple[str, ...]) -> list[Any]:
    """Evenimentele proaspete pentru un set de acțiuni, grupate pe gazdă.

    Gruparea e pe acțiune, nu pe fișier: cinci fișiere atinse de același proces
    în același minut sunt un incident, nu cinci.
    """
    return await db.fetch(
        """
        SELECT e.action,
               count(*)                                             AS n,
               array_agg(DISTINCT e.file_path)
                   FILTER (WHERE e.file_path IS NOT NULL)           AS paths,
               array_agg(DISTINCT e.process)
                   FILTER (WHERE e.process IS NOT NULL)             AS procs,
               array_agg(DISTINCT e.username)
                   FILTER (WHERE e.username IS NOT NULL)            AS users,
               array_agg(e.id ORDER BY e.id DESC)                   AS event_ids,
               min(e.ts) AS first_ts, max(e.ts) AS last_ts,
               (array_agg(e.raw ORDER BY e.id DESC))[1]             AS sample
        FROM raw_events e
        WHERE e.id > $1
          AND e.source = 'auditd'
          AND e.action = ANY($2::text[])
          AND e.ts > now() - make_interval(mins => $3)
        GROUP BY e.action
        """,
        cursor, list(actions), WINDOW_MIN)


def _spec(row: Any, *, rule_id: str, severity: str, title: str,
          summary: str, extra: dict[str, Any] | None = None) -> DetectionSpec:
    users = (row["users"] or [])[:6]
    procs = (row["procs"] or [])[:6]
    return DetectionSpec(
        rule_id=rule_id,
        rule_family="intrusion",
        severity=severity,
        # Fără src_ip: fapta e pe gazdă, iar decidentul nu are ce bloca.
        src_ip=None,
        actor_key="host",
        fingerprint=f"{rule_id}:{row['action']}",
        title=title,
        summary=summary,
        evidence={
            "count": row["n"],
            "paths": [p for p in (row["paths"] or []) if p][:20],
            "processes": procs,
            "auid": users,
            "first_seen": row["first_ts"].isoformat(),
            "last_seen": row["last_ts"].isoformat(),
            "window_min": WINDOW_MIN,
            **(extra or {}),
        },
        event_ids=list(row["event_ids"])[:200],
    )


# ---------------------------------------------------------------------------
# 1. Persistență
# ---------------------------------------------------------------------------
async def persistence(db: Database, cursor: int) -> list[DetectionSpec]:
    """Cheie SSH, cron sau unitate systemd — cum își asigură atacatorul revenirea.

    Critic de la prima apariție. Un `authorized_keys` scris înseamnă acces care
    supraviețuiește schimbării parolei, repornirii și ștergerii procesului care
    l-a pus acolo.
    """
    out: list[DetectionSpec] = []
    for row in await _grouped(db, cursor, ("ssh_key_change", "cron_change", "unit_change")):
        kind = {
            "ssh_key_change": ("chei SSH sau configurație sshd", "acces care supraviețuiește schimbării parolei"),
            "cron_change":    ("sarcini programate", "execuție repetată, la interval, fără sesiune"),
            "unit_change":    ("unități systemd", "execuție la fiecare pornire a serverului"),
        }[row["action"]]
        out.append(_spec(
            row, rule_id=f"intrusion.persistence.{row['action']}", severity="critical",
            title=f"Mecanism de persistență modificat: {kind[0]}",
            summary=(f"{row['n']} modificări în {WINDOW_MIN} min · "
                     f"{_fmt_paths(row['paths'] or [])} · "
                     f"proces: {', '.join((row['procs'] or [])[:3]) or '—'} · "
                     f"auid: {', '.join((row['users'] or [])[:3]) or '—'}. "
                     f"Efectul unei astfel de modificări este {kind[1]}.")))
    return out


# ---------------------------------------------------------------------------
# 2. Escaladare de privilegii
# ---------------------------------------------------------------------------
async def privilege_escalation(db: Database, cursor: int) -> list[DetectionSpec]:
    """sudoers, passwd, shadow — cum își crește atacatorul drepturile.

    O intrare nouă în `/etc/sudoers.d/` e cea mai curată cale de la „am un cont"
    la „sunt root", și e invizibilă pentru orice verificare care se uită doar la
    lista de utilizatori.
    """
    out: list[DetectionSpec] = []
    for row in await _grouped(db, cursor, ("sudoers_change", "identity_change")):
        what = ("reguli sudo" if row["action"] == "sudoers_change"
                else "fișierele de conturi (passwd/shadow/group)")
        out.append(_spec(
            row, rule_id=f"intrusion.privesc.{row['action']}", severity="critical",
            title=f"Escaladare de privilegii: {what} modificate",
            summary=(f"{row['n']} modificări în {WINDOW_MIN} min · "
                     f"{_fmt_paths(row['paths'] or [])} · "
                     f"proces: {', '.join((row['procs'] or [])[:3]) or '—'} · "
                     f"auid: {', '.join((row['users'] or [])[:3]) or '—'}. "
                     f"Verifică dacă modificarea e a ta ÎNAINTE de a face altceva.")))
    return out


# ---------------------------------------------------------------------------
# 3. Autentificare reușită după o rafală de eșecuri
# ---------------------------------------------------------------------------
async def successful_login_after_bruteforce(db: Database, cursor: int) -> list[DetectionSpec]:
    """Semnalul cel mai direct pentru „a intrat".

    Restul motorului alertează pe cele două sute de încercări eșuate. Asta
    alertează pe a două sute una — singura care contează. Fereastra e strânsă
    dinadins: o autentificare reușită la o oră după o rafală e probabil
    administratorul care s-a întors, una la trei minute după e altceva.
    """
    rows = await db.fetch(
        """
        WITH ok AS (
            SELECT id, ts, src_ip, username, geo_country, geo_asn
            FROM raw_events
            WHERE id > $1 AND source = 'sshd' AND action = 'auth_ok'
              AND src_ip IS NOT NULL AND ts > now() - make_interval(mins => $2)
        )
        SELECT host(ok.src_ip) AS ip, ok.username, ok.geo_country, ok.geo_asn,
               ok.id AS ok_id, ok.ts AS ok_ts,
               count(f.id) AS fails,
               min(f.ts)   AS first_fail,
               array_agg(f.id ORDER BY f.id DESC) AS fail_ids
        FROM ok
        JOIN raw_events f
          ON f.src_ip = ok.src_ip AND f.source = 'sshd' AND f.action = 'auth_fail'
         AND f.ts BETWEEN ok.ts - make_interval(mins => $3) AND ok.ts
        GROUP BY ok.id, ok.ts, ok.src_ip, ok.username, ok.geo_country, ok.geo_asn
        HAVING count(f.id) >= $4
        """,
        cursor, WINDOW_MIN, BRUTEFORCE_LOOKBACK_MIN, MIN_FAILS_BEFORE)

    out: list[DetectionSpec] = []
    for r in rows:
        out.append(DetectionSpec(
            rule_id="intrusion.login_after_bruteforce",
            rule_family="intrusion",
            severity="critical",
            src_ip=r["ip"],
            dst_port=22,
            fingerprint=f"intrusion.login_after_bruteforce:{r['ip']}:{r['username']}",
            title=f"Autentificare REUȘITĂ după brute-force · {r['ip']}",
            summary=(f"Contul `{r['username'] or '?'}` s-a autentificat cu succes după "
                     f"{r['fails']} încercări eșuate de la aceeași adresă în ultimele "
                     f"{BRUTEFORCE_LOOKBACK_MIN} min. "
                     f"Țara: {r['geo_country'] or '?'} · ASN: {r['geo_asn'] or '?'}. "
                     f"Dacă nu ești tu, contul e compromis ACUM."),
            evidence={
                "username": r["username"], "fails_before": r["fails"],
                "first_fail": r["first_fail"].isoformat(),
                "success_at": r["ok_ts"].isoformat(),
                "country": r["geo_country"], "asn": r["geo_asn"],
                "lookback_min": BRUTEFORCE_LOOKBACK_MIN,
            },
            event_ids=[r["ok_id"], *list(r["fail_ids"])[:200]],
        ))
    return out


# ---------------------------------------------------------------------------
# 4. Unelte de atacator
# ---------------------------------------------------------------------------
_TOOL = re.compile(r"/(?P<name>[a-z0-9_.-]+)$")


async def attacker_tooling(db: Database, cursor: int) -> list[DetectionSpec]:
    """nc, socat, curl, module de kernel — etapa a doua.

    Severitatea vine din binar, nu din volum: `socat` cu un argument care arată
    a adresă și port e un reverse shell, iar unul singur e suficient.
    """
    rows = await db.fetch(
        """
        SELECT e.id, e.ts, e.process, e.username, e.raw
        FROM raw_events e
        WHERE e.id > $1 AND e.source = 'auditd' AND e.action = 'suspicious_exec'
          AND e.ts > now() - make_interval(mins => $2)
        ORDER BY e.id DESC
        LIMIT 500
        """,
        cursor, WINDOW_MIN)

    by_tool: dict[str, dict[str, Any]] = {}
    for r in rows:
        proc = r["process"] or ""
        m = _TOOL.search(proc)
        name = m["name"] if m else proc
        slot = by_tool.setdefault(name, {"ids": [], "argv": [], "users": set(), "n": 0})
        slot["n"] += 1
        slot["ids"].append(r["id"])
        slot["users"].add(r["username"] or "?")
        raw = r["raw"] if isinstance(r["raw"], dict) else {}
        if raw.get("argv"):
            slot["argv"].append(raw["argv"])

    out: list[DetectionSpec] = []
    for name, slot in by_tool.items():
        sev = TOOL_WEIGHT.get(name, "high")
        argv = slot["argv"][:3]
        out.append(DetectionSpec(
            rule_id=f"intrusion.tooling.{name}",
            rule_family="intrusion",
            severity=sev,
            src_ip=None,
            actor_key="host",
            fingerprint=f"intrusion.tooling:{name}",
            title=f"Unealtă de atacator executată: {name}",
            summary=(f"{slot['n']} execuții în {WINDOW_MIN} min · "
                     f"auid: {', '.join(sorted(slot['users']))[:80]} · "
                     + (f"comandă: `{argv[0][:200]}`" if argv else "fără argumente capturate")),
            evidence={"tool": name, "count": slot["n"],
                      "auid": sorted(slot["users"]), "argv": argv},
            event_ids=slot["ids"][:200],
        ))
    return out


# ---------------------------------------------------------------------------
# 5. Modificare de webroot
# ---------------------------------------------------------------------------
async def webroot_tampering(db: Database, cursor: int) -> list[DetectionSpec]:
    """Scriere în ce servește serverul — webshell, defacement, skimmer.

    Regula cu cel mai mare potențial de fals-pozitive din fișier: pe o gazdă
    unde se face deploy manual, fiecare deploy o declanșează. De aceea e `high`,
    nu `critical`, iar textul spune de la început care e întrebarea de pus.
    """
    out: list[DetectionSpec] = []
    for row in await _grouped(db, cursor, ("webroot_change",)):
        out.append(_spec(
            row, rule_id="intrusion.webroot_tampering", severity="high",
            title="Conținut servit modificat pe disc",
            summary=(f"{row['n']} fișiere scrise în {WINDOW_MIN} min · "
                     f"{_fmt_paths(row['paths'] or [])} · "
                     f"proces: {', '.join((row['procs'] or [])[:3]) or '—'} · "
                     f"auid: {', '.join((row['users'] or [])[:3]) or '—'}. "
                     f"Ai făcut un deploy acum? Dacă nu, verifică fișierele de mai sus.")))
    return out


INTRUSION_RULES = (
    persistence,
    privilege_escalation,
    successful_login_after_bruteforce,
    attacker_tooling,
    webroot_tampering,
)
