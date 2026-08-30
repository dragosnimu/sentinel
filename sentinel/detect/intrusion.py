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

from sentinel.collectors.auditd import SSH_PATH_LIKE
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

# Câte eșecuri fac reușita suspectă. Sub cinci, e un om care și-a greșit
# parola de câteva ori.
#
# Numărate pe ACELAȘI cont ca reușita, nu doar de la aceeași adresă — vezi
# comentariul de la `_BRUTEFORCE_SQL` pentru defectul pe care asta îl repară.
# Rămâne 5, nu cei 20 de la `analytics/insights.py._FORTARE_ESECURI_MIN`,
# fiindcă întreabă altceva: fereastra de-aici e de `BRUTEFORCE_LOOKBACK_MIN`
# minute, sub un singur incident, nu 24h agregate pentru un titlu de pagină.
# Măsurat pe gazdă (29 august 2026, 30 de zile): pentru ORICE autentificare
# reușită reală, `max(eșecuri pe același cont)` e 0 — deci 5 rămâne mult
# deasupra a orice a produs vreodată o reușită legitimă aici, nu doar deasupra
# pragului de „câteva greșeli de tastare" din motivația inițială.
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


async def _grouped(db: Database, cursor: int, actions: tuple[str, ...], *,
                   narrow_action: str | None = None,
                   narrow_paths: tuple[str, ...] | None = None) -> list[Any]:
    """Evenimentele proaspete pentru un set de acțiuni, grupate pe gazdă.

    Gruparea e pe acțiune, nu pe fișier: cinci fișiere atinse de același proces
    în același minut sunt un incident, nu cinci.

    `narrow_action` + `narrow_paths` îngustează O SINGURĂ acțiune după calea
    fișierului, pentru urmăririle pe care nucleul nu le poate îngusta singur.
    `-w /home` nu are cum să spună „doar /home/*/.ssh/", fiindcă auditd nu
    cunoaște globuri; fără filtrul ăsta, scrierea în istoricul de shell al
    oricui ajunge raportată ca schimbare de cheie SSH. Celelalte acțiuni trec
    neatinse — /etc/crontab și /etc/systemd/system sunt deja exact ce ne
    interesează.

    Un eveniment fără cale se elimină din acțiunea îngustată: la o urmărire pe
    fișier, absența căii înseamnă că nu știm ce s-a atins, iar „nu știu" nu e
    motiv de alertă critică.
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
          AND ($4::text IS NULL
               OR e.action <> $4::text
               OR (e.file_path IS NOT NULL AND e.file_path LIKE ANY($5::text[])))
        GROUP BY e.action
        """,
        cursor, list(actions), WINDOW_MIN, narrow_action,
        list(narrow_paths) if narrow_paths else None)


# Ce înseamnă de fapt „schimbare de cheie SSH", odată ce urmărirea de nucleu
# acoperă tot /home. Un director `.ssh` oriunde, plus configurația demonului.
#
# Definiția stă în colector, care aplică acum aceeași îngustare la clasificare —
# o scriere în /home care nu are legătură cu SSH nici nu mai ajunge etichetată
# `ssh_key_change`. Poarta de aici rămâne, cu aceeași listă, din două motive:
# rândurile deja scrise în `raw_events` sub eticheta veche, și faptul că o
# regresie în colector nu are voie să redeschidă alertele critice pe nimic.
# Două liste separate ar fi divergat, iar divergența s-ar fi văzut ca un
# fals-negativ tăcut.
SSH_PATHS = SSH_PATH_LIKE


def _spec(row: Any, *, rule_id: str, severity: str, title: str,
          summary: str, extra: dict[str, Any] | None = None,
          path_backed: bool = True) -> DetectionSpec:
    """`path_backed` implicit adevărat: toate regulile de mai jos, în afară de
    încărcarea de module, spun „fișierul X s-a modificat". Vezi
    `spec.enforce_path_evidence` pentru ce se întâmplă când X lipsește."""
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
        path_backed=path_backed,
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
    for row in await _grouped(db, cursor,
                              ("ssh_key_change", "cron_change", "unit_change"),
                              narrow_action="ssh_key_change",
                              narrow_paths=SSH_PATHS):
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
#
# Reparat pe același defect ca `analytics/insights.py._FORTARE_SQL` (vezi
# comentariul de-acolo, 28 august 2026): forma veche cerea doar COEXISTENȚA —
# aceeași adresă avea ≥5 eșecuri în fereastră ȘI o reușită oarecare — nu
# CAUZALITATEA. Pe gazda asta asta a însemnat un „🔴 Autentificare reușită de
# la un atacator" pentru o sesiune de deploy: trei refuzuri pe `dragos`,
# `deploy` și `admin`, apoi o reușită pe `sentinel-deploy` de pe ACEEAȘI
# adresă — alt cont, deci nimic spart. Reluată peste 30 de zile de date reale,
# regula veche a dat zero rânduri: nu e o pană în așteptare, e o mină care n-a
# explodat încă doar fiindcă nimeni n-a reușit să intre de pe o adresă care și
# eșuase des.
#
# Doi eșecuri o mai leagă de reușită: cont și metodă.
#   * `f.username = ok.username` — o forțare care reușește, reușește pe
#     contul pe care îl atacă. Eșecurile pe `admin` nu spun nimic despre o
#     reușită pe `sentinel-deploy`.
#   * `auth_method IS DISTINCT FROM 'publickey'`, pe reușită ȘI pe eșecuri —
#     o cheie nu se ghicește, deci o reușită pe cheie nu e o forțare care a
#     mers, indiferent câte eșecuri au precedat-o (un agent ssh cu mai multe
#     chei încărcate emite câte un refuz per cheie pe aceeași conexiune,
#     ceea ce a produs exact cele trei „atacuri" de mai sus în trei secunde).
#     `IS DISTINCT FROM`, nu `<>`: o metodă NECUNOSCUTĂ (parserul sshd n-o
#     scrie pe liniile „Invalid user") tot trebuie numărată — necunoscut nu
#     e sigur.
#
# `ok.username` poate lipsi (unele metode nu-l scriu pe linia de succes).
# Atunci contul nu poate fi verificat, deci SQL-ul întoarce și eșecurile pe
# toată adresa, iar Python alege: cu cont — dovadă tare; fără — dovadă mai
# slabă, dar tăcerea aici ar fi aceeași minciună ca regula veche, doar
# întoarsă pe dos.
_BRUTEFORCE_SQL = """
    WITH ok AS (
        SELECT id, ts, src_ip, username, geo_country, geo_asn,
               raw->>'auth_method' AS metoda
        FROM raw_events
        WHERE id > $1 AND source = 'sshd' AND action = 'auth_ok'
          AND src_ip IS NOT NULL AND ts > now() - make_interval(mins => $2)
          AND raw->>'auth_method' IS DISTINCT FROM 'publickey'
    )
    SELECT host(ok.src_ip) AS ip, ok.username, ok.geo_country, ok.geo_asn,
           ok.metoda, ok.id AS ok_id, ok.ts AS ok_ts,
           coalesce(count(f.id) FILTER (WHERE f.username = ok.username), 0)
               AS fails_cont,
           coalesce(count(f.id), 0) AS fails_ip,
           min(f.ts) FILTER (WHERE f.username = ok.username) AS first_fail_cont,
           min(f.ts) AS first_fail_ip,
           array_agg(f.id ORDER BY f.id DESC)
               FILTER (WHERE f.username = ok.username) AS fail_ids_cont,
           array_agg(f.id ORDER BY f.id DESC) AS fail_ids_ip
    FROM ok
    LEFT JOIN raw_events f
      ON f.src_ip = ok.src_ip AND f.source = 'sshd' AND f.action = 'auth_fail'
     AND f.raw->>'auth_method' IS DISTINCT FROM 'publickey'
     AND f.ts BETWEEN ok.ts - make_interval(mins => $3) AND ok.ts
    GROUP BY ok.id, ok.ts, ok.src_ip, ok.username, ok.geo_country, ok.geo_asn,
             ok.metoda
"""  # noqa: S608 - SQL din constante de modul, nu din date de la cineva


async def successful_login_after_bruteforce(db: Database, cursor: int) -> list[DetectionSpec]:
    """Semnalul cel mai direct pentru „a intrat".

    Restul motorului alertează pe cele două sute de încercări eșuate. Asta
    alertează pe a două sute una — singura care contează. Fereastra e strânsă
    dinadins: o autentificare reușită la o oră după o rafală e probabil
    administratorul care s-a întors, una la trei minute după e altceva.

    Nu orice reușită după eșecuri e o forțare care a mers — vezi comentariul
    de la `_BRUTEFORCE_SQL` pentru cont și metodă, cele două lucruri care o
    deosebesc de o coincidență.
    """
    rows = await db.fetch(
        _BRUTEFORCE_SQL, cursor, WINDOW_MIN, BRUTEFORCE_LOOKBACK_MIN)

    out: list[DetectionSpec] = []
    for r in rows:
        # A doua gardă pe metodă: `_BRUTEFORCE_SQL` deja exclude reușitele pe
        # cheie, dar asta ține garda vizibilă și aici, ca la
        # `insights.posture` — cine editează CTE-ul mai târziu nu poate șterge
        # apărarea din greșeală, doar optimizarea.
        if r["metoda"] == "publickey":
            continue
        cont = r["username"]
        if cont is None:
            fails = int(r["fails_ip"] or 0)
            first_fail = r["first_fail_ip"]
            fail_ids = r["fail_ids_ip"] or []
        else:
            fails = int(r["fails_cont"] or 0)
            first_fail = r["first_fail_cont"]
            fail_ids = r["fail_ids_cont"] or []
        if fails < MIN_FAILS_BEFORE:
            continue
        out.append(DetectionSpec(
            rule_id="intrusion.login_after_bruteforce",
            rule_family="intrusion",
            severity="critical",
            src_ip=r["ip"],
            dst_port=22,
            fingerprint=f"intrusion.login_after_bruteforce:{r['ip']}:{cont}",
            title=f"Autentificare REUȘITĂ după brute-force · {r['ip']}",
            summary=(f"Contul `{cont or '?'}` s-a autentificat cu succes după "
                     f"{fails} încercări eșuate "
                     f"{'pe același cont' if cont is not None else 'de la aceeași adresă'} "
                     f"în ultimele {BRUTEFORCE_LOOKBACK_MIN} min. "
                     f"Țara: {r['geo_country'] or '?'} · ASN: {r['geo_asn'] or '?'}. "
                     f"Dacă nu ești tu, contul e compromis ACUM."),
            evidence={
                "username": cont, "fails_before": fails,
                "first_fail": first_fail.isoformat() if first_fail else None,
                "success_at": r["ok_ts"].isoformat(),
                "country": r["geo_country"], "asn": r["geo_asn"],
                "lookback_min": BRUTEFORCE_LOOKBACK_MIN,
            },
            event_ids=[r["ok_id"], *list(fail_ids)[:200]],
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
        # Only binaries this rule has an opinion about. It used to default
        # unknown names to `high` and title them "attacker tool executed",
        # which is how `install`, `chmod` and `logrotate` were reported as
        # attacker tooling for two days. The kernel rules are narrow again, so
        # nothing else should arrive here — but a rule whose failure mode is
        # crying wolf does not get to rely on that.
        sev = TOOL_WEIGHT.get(name)
        if sev is None:
            continue
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




# ---------------------------------------------------------------------------
# 6. Conturi: evenimentul
# ---------------------------------------------------------------------------
async def account_created(db: Database, cursor: int) -> list[DetectionSpec]:
    """`useradd`, `usermod`, `groupadd` — cu numele contului.

    Regula de escaladare de mai sus spune CĂ s-a scris în `/etc/passwd`. Asta
    spune CE cont a apărut, ceea ce e diferența dintre o alertă pe care o
    investighezi și una pe care o poți judeca din prima citire.

    Sursa e alta: auditd emite ADD_USER / USER_MGMT ca înregistrări de sine
    stătătoare, cu câmpul `acct`, independent de supravegherea pe fișier. Dacă
    una dintre cele două căi e ocolită, cealaltă rămâne.
    """
    rows = await db.fetch(
        """
        SELECT e.id, e.ts, e.username, e.process, e.src_ip, e.raw
        FROM raw_events e
        WHERE e.id > $1 AND e.source = 'auditd' AND e.action = 'account_change'
          AND e.ts > now() - make_interval(mins => $2)
        ORDER BY e.id DESC LIMIT 200
        """,
        cursor, WINDOW_MIN)
    if not rows:
        return []

    by_acct: dict[str, dict[str, Any]] = {}
    for r in rows:
        raw = r["raw"] if isinstance(r["raw"], dict) else {}
        acct = raw.get("acct") or r["username"] or "?"
        slot = by_acct.setdefault(acct, {"ids": [], "ops": set(), "n": 0,
                                         "by": set(), "types": set()})
        slot["n"] += 1
        slot["ids"].append(r["id"])
        if raw.get("op"):
            slot["ops"].add(raw["op"][:60])
        if raw.get("record_type"):
            slot["types"].add(raw["record_type"])
        slot["by"].add(raw.get("auid") or raw.get("uid") or "?")

    out: list[DetectionSpec] = []
    for acct, slot in by_acct.items():
        ops = ", ".join(sorted(slot["ops"])) or ", ".join(sorted(slot["types"])) or "modificare"
        out.append(DetectionSpec(
            rule_id="intrusion.account_change",
            rule_family="intrusion",
            severity="critical",
            src_ip=None,
            actor_key="host",
            fingerprint=f"intrusion.account_change:{acct}",
            title=f"Cont de sistem modificat: {acct}",
            summary=(f"Operație: {ops} · executată de auid {', '.join(sorted(slot['by']))} · "
                     f"{slot['n']} înregistrări în {WINDOW_MIN} min. "
                     f"Dacă nu ai creat tu contul `{acct}`, cineva își asigură accesul."),
            evidence={"account": acct, "operations": sorted(slot["ops"]),
                      "record_types": sorted(slot["types"]),
                      "by_auid": sorted(slot["by"]), "count": slot["n"]},
            event_ids=slot["ids"][:200],
        ))
    return out


# Definit la final: fiecare regulă trebuie să existe înainte de a fi numită aici,
# iar un tuplu care numește o funcție definită mai jos pică la import — adică
# serviciul nu pornește deloc, în loc să eșueze o singură regulă.
# ---------------------------------------------------------------------------
# 7. Un binar a devenit setuid
# ---------------------------------------------------------------------------
async def suid_change(db: Database, cursor: int) -> list[DetectionSpec]:
    """`chmod u+s` — cea mai curată ușă din dos pe care o poate lăsa cineva.

    Un binar setuid-root scris de un utilizator obișnuit înseamnă că acel
    utilizator poate redeveni root oricând, fără parolă, fără sudo, fără urmă
    în jurnalul de autentificare. E o singură comandă, e reversibilă în două
    secunde, și supraviețuiește repornirii.

    Semnalul ăsta exista de la început în regulile de nucleu, dar împărțea
    cheia cu uneltele de rețea, deci ajungea în regula de tooling și era
    raportat ca „unealtă de atacator executată: chmod". Adevărata întrebare —
    CE fișier a devenit setuid — nu apărea nicăieri.
    """
    out: list[DetectionSpec] = []
    for row in await _grouped(db, cursor, ("suid_change",)):
        out.append(_spec(
            row, rule_id="intrusion.suid_change", severity="critical",
            title="Bit setuid/setgid pus pe un fișier",
            summary=(f"{row['n']} modificări de mod în {WINDOW_MIN} min · "
                     f"{_fmt_paths(row['paths'] or [])} · "
                     f"proces: {', '.join((row['procs'] or [])[:3]) or '—'} · "
                     f"auid: {', '.join((row['users'] or [])[:3]) or '—'}. "
                     f"Un binar setuid-root înseamnă root fără parolă, la cerere. "
                     f"Verifică fișierul înainte de orice altceva.")))
    return out


# ---------------------------------------------------------------------------
# 8. Modul de kernel încărcat
# ---------------------------------------------------------------------------
async def module_load(db: Database, cursor: int) -> list[DetectionSpec]:
    """Sub kernel nu mai există nimic care să observe.

    Pe o gazdă care nu încarcă module proprii, o inserție e ori o actualizare
    de sistem, ori un rootkit. Diferența nu se poate face din spațiul
    utilizatorului — care e exact motivul pentru care merită întrebat.

    Fără filtru pe `auid`, spre deosebire de restul: un modul care sosește fără
    nicio sesiune de autentificare în spate e mai alarmant, nu mai puțin.
    """
    out: list[DetectionSpec] = []
    for row in await _grouped(db, cursor, ("module_load",)):
        out.append(_spec(
            # Singura regulă din fișier care nu susține nimic despre un fișier:
            # `init_module` nu are înregistrare PATH, iar textul alertei nu
            # promite una. Garda pe evidență ar retrograda-o pe nedrept.
            row, rule_id="intrusion.module_load", severity="critical",
            path_backed=False,
            title="Modul de kernel încărcat sau descărcat",
            summary=(f"{row['n']} operații în {WINDOW_MIN} min · "
                     f"proces: {', '.join((row['procs'] or [])[:3]) or '—'} · "
                     f"auid: {', '.join((row['users'] or [])[:3]) or '—'}. "
                     f"Dacă nu ai actualizat nucleul sau un driver acum, "
                     f"nimic din ce rulează pe gazda asta nu mai poate fi crezut.")))
    return out


INTRUSION_RULES = (
    persistence,
    privilege_escalation,
    successful_login_after_bruteforce,
    attacker_tooling,
    webroot_tampering,
    account_created,
    suid_change,
    module_load,
)
