"""Auditul stării conturilor: ce scrie ACUM în /etc/passwd.

Restul detecției e bazată pe evenimente: kernelul raportează o scriere, noi o
citim. E rapidă și precisă, și are o slăbiciune structurală — poate fi ocolită.
Un atacator care a ajuns root oprește `auditd`, își adaugă contul, îl repornește.
Nu rămâne niciun eveniment, iar toate regulile bazate pe evenimente tac.

Verificarea de aici nu se uită la ce s-a raportat, ci la ce E. Citește
`/etc/passwd` la fiecare trecere și compară cu ce a văzut ultima dată. Un cont
apărut între două citiri se vede indiferent dacă cineva a raportat apariția lui.

## Cele două întrebări

**„E vreun al doilea root?"** are răspuns absolut, nu învățat. Un Linux standard
are exact un cont cu uid 0. Un al doilea e, practic fără excepție, o ușă din
spate — de aceea alertează chiar și la prima citire, fără linie de bază.

**„A apărut un cont nou?"** are nevoie de o linie de bază, fiindcă la prima
citire toate conturile sunt „noi". Prima trecere le înregistrează în tăcere;
de la a doua, orice adăugare alertează.

## Limita, spusă în cod ca să nu fie descoperită la nevoie

Dacă Sentinel se instalează pe un server DEJA compromis, contul atacatorului
intră în linia de bază ca normal. Verificarea aia nu îl va găsi niciodată. Doar
regula pe uid 0 rămâne utilă în cazul ăsta, fiindcă nu depinde de istoric.

## Despre /etc/shadow

Nu poate fi citit: e `0640 root:shadow`, iar serviciul rulează ca `sentinel`.
Se urmărește doar `mtime` și dimensiunea, ceea ce răspunde la „s-a schimbat?",
nu la „ce s-a schimbat". Suficient ca semnal, insuficient ca explicație — și
spus ca atare în textul alertei, ca operatorul să nu creadă că știm mai mult
decât știm.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from sentinel.db.engine import Database
from sentinel.detect.spec import DetectionSpec
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

PASSWD = "/etc/passwd"
SHADOW = "/etc/shadow"

# Dimensiunea sub care se ține linia de bază. Aceeași tabelă ca profilul de
# comportament, fiindcă întrebarea e aceeași — „am mai văzut asta?" — dar FĂRĂ
# poarta de încălzire: un al doilea cont root nu așteaptă trei zile.
DIM_ACCOUNT = "system_account"
DIM_FILE = "system_file_state"

# Shell-uri care înseamnă „contul ăsta nu e făcut pentru login". Un cont de
# serviciu care capătă brusc un shell interactiv e semnalul, nu contul în sine.
NOLOGIN = frozenset({"/sbin/nologin", "/usr/sbin/nologin", "/bin/false",
                     "/usr/bin/false", "", "/dev/null"})


def _read_passwd(path: str = PASSWD) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(":")
                if len(parts) < 7 or line.startswith("#"):
                    continue
                try:
                    uid = int(parts[2])
                except ValueError:
                    continue
                out.append({"name": parts[0], "uid": uid, "gid": parts[3],
                            "home": parts[5], "shell": parts[6]})
    except OSError as exc:
        log.warning("cannot read passwd", extra={"path": path, "detail": str(exc)})
    return out


def _file_state(path: str) -> str | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    # Fără conținut: doar cât de mare e și când a fost atins ultima dată.
    return f"{int(st.st_mtime)}:{st.st_size}"


def _signature(acc: dict[str, Any]) -> str:
    """Ce face un cont să fie „același" cont.

    Include shell-ul dinadins: `nobody` care capătă `/bin/bash` trebuie să arate
    ca o schimbare, nu ca același rând nemodificat.
    """
    return f"{acc['name']}:{acc['uid']}:{acc['shell']}"


async def _seen(db: Database, dimension: str) -> set[str]:
    rows = await db.fetch(
        "SELECT key FROM behaviour_profiles WHERE dimension = $1", dimension)
    return {r["key"] for r in rows}


async def _remember(db: Database, dimension: str, keys: set[str]) -> None:
    for k in keys:
        await db.execute(
            """
            INSERT INTO behaviour_profiles (dimension, key) VALUES ($1, $2)
            ON CONFLICT (dimension, key) DO UPDATE SET last_seen = now(),
                observations = behaviour_profiles.observations + 1
            """,
            dimension, k)


async def account_state_audit(db: Database, cursor: int) -> list[DetectionSpec]:
    accounts = await asyncio.to_thread(_read_passwd)
    if not accounts:
        return []          # nu putem citi; tăcerea e mai bună decât o alertă falsă

    known = await _seen(db, DIM_ACCOUNT)
    first_run = not known
    current = {_signature(a): a for a in accounts}
    fresh = {k: v for k, v in current.items() if k not in known}

    out: list[DetectionSpec] = []

    # --- al doilea root: absolut, nu învățat -------------------------------
    roots = [a for a in accounts if a["uid"] == 0]
    extra_roots = [a for a in roots if a["name"] != "root"]
    if extra_roots:
        names = ", ".join(a["name"] for a in extra_roots)
        out.append(DetectionSpec(
            rule_id="intrusion.uid0_account",
            rule_family="intrusion",
            severity="critical",
            src_ip=None,
            actor_key="host",
            fingerprint=f"intrusion.uid0_account:{names}",
            title=f"Cont cu privilegii de root: {names}",
            summary=(f"`/etc/passwd` conține {len(roots)} conturi cu uid 0: "
                     + ", ".join(f"`{a['name']}`" for a in roots) + ". "
                     "Un sistem Linux standard are exact unul. Un al doilea e, "
                     "practic fără excepție, o ușă din spate."
                     + (" Găsit la prima citire — poate fi anterior instalării "
                        "Sentinel, deci verifică de când există."
                        if first_run else "")),
            evidence={"uid0_accounts": [a["name"] for a in extra_roots],
                      "all_uid0": [a["name"] for a in roots],
                      "found_on_first_run": first_run},
            event_ids=[],
        ))

    # --- conturi noi ------------------------------------------------------
    if first_run:
        # Prima trecere înregistrează în tăcere. Alternativa ar fi o alertă
        # pentru fiecare cont de sistem al distribuției, în prima secundă.
        await _remember(db, DIM_ACCOUNT, set(current))
        log.info("account baseline recorded", extra={"accounts": len(current)})
    elif fresh:
        interactive = [a for a in fresh.values() if a["shell"] not in NOLOGIN]
        for acc in fresh.values():
            login = acc["shell"] not in NOLOGIN
            out.append(DetectionSpec(
                rule_id="intrusion.new_account",
                rule_family="intrusion",
                severity="critical" if login else "high",
                src_ip=None,
                actor_key="host",
                fingerprint=f"intrusion.new_account:{acc['name']}:{acc['uid']}",
                title=(f"Cont nou cu shell de login: {acc['name']}" if login
                       else f"Cont de sistem nou: {acc['name']}"),
                summary=(f"`{acc['name']}` (uid {acc['uid']}, shell `{acc['shell']}`, "
                         f"home `{acc['home']}`) nu exista la ultima citire a "
                         f"`/etc/passwd`. "
                         + ("Are shell interactiv, deci se poate autentifica."
                            if login else
                            "Nu are shell de login, deci nu se poate autentifica "
                            "direct — dar poate rula prin cron sau prin systemd.")),
                evidence={"account": acc["name"], "uid": acc["uid"],
                          "shell": acc["shell"], "home": acc["home"],
                          "can_login": login},
                event_ids=[],
            ))
        await _remember(db, DIM_ACCOUNT, set(fresh))
        log.warning("new accounts in passwd",
                    extra={"accounts": [a["name"] for a in fresh.values()],
                           "interactive": [a["name"] for a in interactive]})

    # --- shadow: s-a schimbat, fără să putem spune cum --------------------
    out += await _shadow_changed(db)
    return out


async def _shadow_changed(db: Database) -> list[DetectionSpec]:
    state = await asyncio.to_thread(_file_state, SHADOW)
    if state is None:
        return []
    key = f"{SHADOW}:{state}"
    known = await _seen(db, DIM_FILE)
    prior = {k for k in known if k.startswith(f"{SHADOW}:")}
    await _remember(db, DIM_FILE, {key})
    if not prior or key in prior:
        return []

    return [DetectionSpec(
        rule_id="intrusion.shadow_changed",
        rule_family="intrusion",
        severity="high",
        src_ip=None,
        actor_key="host",
        fingerprint="intrusion.shadow_changed",
        title="/etc/shadow a fost modificat",
        summary=("Fișierul cu parolele conturilor s-a schimbat de la ultima "
                 "citire. Conținutul nu poate fi citit — e `0640 root:shadow`, "
                 "iar Sentinel nu rulează ca root — deci știm CĂ s-a schimbat, "
                 "nu ce anume. O schimbare de parolă arată la fel ca un cont nou. "
                 "Corelează cu alertele de conturi din aceeași perioadă."),
        evidence={"path": SHADOW, "previous": sorted(prior)[-1] if prior else None,
                  "current": key},
        event_ids=[],
    )]


ACCOUNT_RULES = (account_state_audit,)
