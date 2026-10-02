"""Ce au în comun oglinzile de risc: client HTTP, vârste, `intel_state`.

`kev.py` e modelul: o sursă publică, oglindită în Postgres, citită local. Cele
trei oglinzi noi (`epss.py`, `redhat.py`, `osv.py`) adaugă o a doua regulă la
prima — „o încercare eșuată nu e o scanare eșuată" — și o a treia, care e pricina
acestui fișier: **un eșec trebuie să rămână vizibil**. `kev.refresh` loghează un
WARNING și întoarce 0, iar 0 înseamnă și „era la zi". Aici, fiecare încercare își
scrie rezultatul în `intel_state` (`last_attempt_at`, `last_ok_at`,
`last_error`), ca „sursa e căzută de nouă zile" să se poată deosebi de „sursa e
la zi și doar nu are CVE-ul ăsta".

Al patrulea fapt, măsurat pe 2 octombrie 2026: **„n-am avut nimic de cerut" și „am
cerut și a eșuat" trebuie să arate diferit în `intel_state`**. O trecere în care
nimic nu e la termen (răspunsurile reținute sunt încă proaspete: 7 zile pentru un CVE
evaluat, 2 pentru unul neevaluat) nu primește niciun răspuns, deci `last_ok_at` nu
se mișcă, iar autoverificarea îl citea ca „sursa nu mai răspunde de 36 de ore" —
adică sună `degraded` după 36 de ore de liniște, nu după 36 de ore de eșec. Soluția
nu e să se mute `last_ok_at` (ar însemna „sursa a răspuns acum", ceea ce nu s-a
întâmplat: nimeni n-a întrebat): `record_idle` mișcă DOAR `last_attempt_at` și
scrie `detail.idle = true`. `last_ok_at` rămâne „ultimul răspuns real"; trecerea
liniștită e un fapt separat, cu vârsta ei, iar autoverificarea le citește pe amândouă.
Un eșec nu poate trece drept liniște: ce a eșuat rămâne la termen, deci trecerea
următoare cere din nou, iar o trecere care a cerut nu e niciodată `idle`.

Nimic din fișierul ăsta nu ridică spre apelant: o oglindă care strică scanarea
transformă o sursă opțională într-un mod de eșec.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

#: Cât timp așteaptă o cerere. Red Hat a răspuns în ~0,5 s pe cerere (1482 de
#: cereri secvențiale în 707 s, 2 octombrie 2026); plafonul larg e pentru
#: răspunsurile lente ocazionale, care nu sunt un eșec.
TIMEOUT_S = 30.0

#: Politețe: pauza dintre două cereri către aceeași sursă, secvențial. Volumul
#: zilnic real e de ordinul zecilor (CVE-urile NOI), nu al miilor.
PAUSE_S = 0.25

#: După câte eșecuri consecutive se oprește o sursă într-o trecere. Un API
#: care răspunde 5xx de cinci ori la rând nu devine mai bun la a șasea cerere.
MAX_CONSECUTIVE_ERRORS = 5

#: Identificare onestă. Cele trei servicii sunt publice și fără cheie; politețea
#: lor se bazează pe a ști cine bate la ușă.
USER_AGENT = "sentinel-security-agent (local mirror of public vulnerability data)"

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,19}$")
#: GHSA-xxxx-xxxx-xxxx, litere mici și cifre, cum le scrie GitHub. Validarea
#: există fiindcă id-ul ajunge în calea unui URL, iar valoarea vine din ieșirea
#: unui scaner.
GHSA_ID = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$")


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=TIMEOUT_S, follow_redirects=True, http2=False,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"})


async def record(db: Database, source: str, *, ok: bool, error: str | None = None,
                 detail: dict[str, Any] | None = None) -> None:
    """Scrie rezultatul unei încercări. Niciodată nu ridică.

    `last_ok_at` se mișcă DOAR la succes. `last_error` se șterge la un succes
    curat, ca o eroare veche să nu stea lângă o sursă care s-a vindecat, dar un
    succes PARȚIAL (unele căutări au răspuns, altele nu) își păstrează eroarea:
    „a mers pe jumătate" nu e „a mers".
    """
    await _upsert(db, source, answered=ok,
                  error=error[:300] if error else (None if ok else "eșec fără detalii"),
                  detail=detail)


async def record_idle(db: Database, source: str,
                      detail: dict[str, Any] | None = None) -> None:
    """Scrie că o trecere a ajuns la sursă și n-avea nimic de cerut. Niciodată nu ridică.

    NU mișcă `last_ok_at`: el rămâne momentul ultimului răspuns REAL al sursei, iar o
    trecere care n-a întrebat pe nimeni nu poate pretinde că sursa a răspuns. Mișcă
    `last_attempt_at` (dovada că trecerea a ajuns aici, deci că tăcerea e liniște și nu
    o trecere oprită) și șterge `last_error`: dacă ar fi rămas ceva de reluat, ar fi fost
    la termen și trecerea n-ar fi fost liniștită. `detail` primește `idle: true`, singurul
    semn pe care îl citește autoverificarea pentru a deosebi liniștea de un eșec.
    """
    await _upsert(db, source, answered=False, error=None,
                  detail={**(detail or {}), "idle": True})


async def _upsert(db: Database, source: str, *, answered: bool, error: str | None,
                  detail: dict[str, Any] | None) -> None:
    try:
        await db.execute(
            """
            INSERT INTO intel_state (source, last_attempt_at, last_ok_at, last_error, detail)
            VALUES ($1, now(), CASE WHEN $2::boolean THEN now() END, $3, $4::jsonb)
            ON CONFLICT (source) DO UPDATE SET
                last_attempt_at = now(),
                last_ok_at = CASE WHEN $2::boolean THEN now()
                                  ELSE intel_state.last_ok_at END,
                last_error = $3,
                detail = $4::jsonb
            """,
            source, answered, error, json.dumps(detail or {}))
    except Exception as exc:  # noqa: BLE001 - jurnalul stării nu are voie să strice scanarea
        log.warning("intel_state nu s-a putut scrie",
                    extra={"source": source, "detail": str(exc)[:200]})


async def state(db: Database, source: str) -> dict[str, Any] | None:
    row = await db.fetchrow(
        "SELECT last_attempt_at, last_ok_at, last_error, detail "
        "FROM intel_state WHERE source = $1", source)
    return dict(row) if row else None


def hours_since(moment: datetime | None, *, now: datetime | None = None) -> float | None:
    """Ore trecute de la `moment`, sau `None` dacă nu există."""
    if moment is None:
        return None
    now = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (now - moment).total_seconds() / 3600


# ---------------------------------------------------------------------------
# Căutări pe id (Red Hat, OSV): aceeași buclă, ca să nu se despartă regulile
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Outcome:
    """Răspunsul unei singure cereri.

    `error` NU se scrie în oglindă: o cerere picată (timeout, 5xx, 429, un
    răspuns pe care nu-l putem citi) nu e un răspuns despre CVE, iar scrisă ca
    `not_found` ar ascunde CVE-ul o săptămână întreagă. Se reia la trecerea
    următoare.
    """
    kind: str                      # "found" | "not_found" | "error"
    record: dict[str, Any] | None = None
    error: str | None = None


VulnFetch = Callable[[httpx.AsyncClient, str], Awaitable[Outcome]]


async def store_vuln(db: Database, vuln_id: str, source: str, outcome: Outcome) -> None:
    """Scrie un răspuns `found` / `not_found` în `vuln_intel`."""
    rec = outcome.record or {}
    await db.execute(
        """
        INSERT INTO vuln_intel (vuln_id, source, status, cvss_score, cvss_vector,
                                cvss_version, severity, justification, aliases,
                                advisories, fetched_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text[], $10::text[], now())
        ON CONFLICT (vuln_id, source) DO UPDATE SET
            status = EXCLUDED.status, cvss_score = EXCLUDED.cvss_score,
            cvss_vector = EXCLUDED.cvss_vector, cvss_version = EXCLUDED.cvss_version,
            severity = EXCLUDED.severity, justification = EXCLUDED.justification,
            aliases = EXCLUDED.aliases, advisories = EXCLUDED.advisories,
            fetched_at = now()
        """,
        vuln_id, source, outcome.kind,
        rec.get("cvss_score"), rec.get("cvss_vector"), rec.get("cvss_version"),
        rec.get("severity"), rec.get("justification"),
        list(rec.get("aliases") or []), list(rec.get("advisories") or []))


async def due(db: Database, source: str, ids: set[str], *, found_days: float,
              unrated_days: float, not_found_days: float,
              now: datetime | None = None) -> list[str]:
    """Id-urile din `ids` care trebuie (re)cerute, în ordine stabilă.

    Un rând `found` cu scor se reia după `found_days` (furnizorii își
    reevaluează CVE-urile). Unul `found` FĂRĂ vector se reia mult mai des
    (`unrated_days`): o vulnerabilitate proaspătă primește evaluarea în zile.
    Un `not_found` se reia după `not_found_days` (un CVE rezervat azi apare
    mâine). Lipsa rândului înseamnă „niciodată cerut".
    """
    if not ids:
        return []
    rows = await db.fetch(
        """
        SELECT vuln_id, status, cvss_vector, fetched_at
        FROM vuln_intel WHERE source = $1 AND vuln_id = ANY($2::text[])
        """,
        source, sorted(ids))
    have = {r["vuln_id"]: r for r in rows}
    now = now or datetime.now(timezone.utc)
    out: list[str] = []
    for vid in sorted(ids):
        row = have.get(vid)
        if row is None:
            out.append(vid)
            continue
        age_days = (hours_since(row["fetched_at"], now=now) or 0.0) / 24
        if row["status"] == "not_found":
            limit = not_found_days
        elif row["cvss_vector"] is None:
            limit = unrated_days
        else:
            limit = found_days
        if age_days >= limit:
            out.append(vid)
    return out


async def run_lookups(db: Database, source: str, ids: list[str], fetch: VulnFetch, *,
                      http: httpx.AsyncClient | None, budget: int,
                      pause_s: float = PAUSE_S,
                      store: Callable[[Database, str, Outcome], Awaitable[None]] | None = None,
                      ) -> dict[str, Any]:
    """Cere `ids` pe rând, scrie ce a răspuns sursa, și spune cum a mers.

    Secvențial și cu pauză: volumul zilnic real e de ordinul zecilor. Se oprește
    la `budget` cereri (restul se reiau la trecerea următoare, nu se pierd) și
    după `MAX_CONSECUTIVE_ERRORS` eșecuri la rând. Niciodată nu ridică.

    `store` scrie un răspuns `found` / `not_found`; implicit `store_vuln`
    (`vuln_intel`, Red Hat și OSV). O sursă cu altă formă de rând (Vulnrichment)
    își dă scrierea, iar restul regulilor — plafon, oprire după eșecuri, nicio
    cerere picată scrisă ca „nu există" — rămân aceleași, într-un singur loc.

    Cu `ids` gol (nimic la termen) nu cere nimic și scrie `record_idle`, nu `record`:
    „n-am avut ce întreba" nu e „sursa a răspuns" și nu e „sursa a eșuat".
    """
    write = store or (lambda d, vid, outcome: store_vuln(d, vid, source, outcome))
    summary: dict[str, Any] = {"asked": 0, "found": 0, "not_found": 0, "errors": 0,
                               "deferred": 0, "aborted": False, "idle": False}
    if not ids:
        # Nimic la termen: nu e un răspuns (`last_ok_at` rămâne) și nu e un eșec; e o
        # trecere liniștită, pe care autoverificarea trebuie s-o poată deosebi de un
        # silențiu al trecerii. Fără rândul ăsta, 36 de ore fără CVE la termen sunau
        # „căutările eșuează" pe două gazde în care nimic nu eșuase.
        summary["idle"] = True
        await record_idle(db, source, dict(summary))
        return summary
    owns = http is None
    http = http or client()
    consecutive = 0
    last_error: str | None = None
    try:
        for index, vid in enumerate(ids):
            if summary["asked"] >= budget:
                summary["deferred"] = len(ids) - index
                break
            if consecutive >= MAX_CONSECUTIVE_ERRORS:
                summary["aborted"] = True
                summary["deferred"] = len(ids) - index
                break
            if summary["asked"]:
                await asyncio.sleep(pause_s)
            summary["asked"] += 1
            try:
                outcome = await fetch(http, vid)
            except Exception as exc:  # noqa: BLE001 - `fetch` nu are voie să strice trecerea
                outcome = Outcome("error", error=f"{type(exc).__name__}: {exc}"[:200])
            if outcome.kind == "error":
                consecutive += 1
                summary["errors"] += 1
                last_error = outcome.error
                continue
            consecutive = 0
            try:
                await write(db, vid, outcome)
            except Exception as exc:  # noqa: BLE001
                summary["errors"] += 1
                last_error = f"scriere: {type(exc).__name__}: {exc}"[:200]
                continue
            summary[outcome.kind] += 1
    finally:
        if owns:
            await http.aclose()
    answered = summary["found"] + summary["not_found"]
    ok = answered > 0 or summary["errors"] == 0
    if summary["aborted"]:
        ok = False
    await record(db, source, ok=ok, error=last_error, detail=dict(summary))
    if summary["errors"]:
        log.warning("căutări eșuate la sursa de risc",
                    extra={"source": source, **summary, "detail": last_error})
    return summary
