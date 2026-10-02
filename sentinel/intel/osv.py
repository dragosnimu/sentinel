"""OSV.dev — vectorul CVSS și aliasurile pentru ce nu vine de la Red Hat.

`api.osv.dev/v1/vulns/<id>` răspunde fără cheie, pentru id-uri CVE și GHSA, cu
`severity: [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}]` (vectorul, nu
numărul), `aliases` (celelalte id-uri ale aceleiași vulnerabilități) și, la
avizele GitHub, `database_specific.severity` (LOW/MODERATE/HIGH/CRITICAL).

## Ce rezolvă aici, măsurat pe producție (2 octombrie 2026)

  * 36 de constatări trivy deschise nu aveau CVSS; OSV a dat un vector pentru 31
    din cele 32 de id-uri distincte (unul a răspuns 404).
  * 29 de constatări deschise n-au CVE, doar un `GHSA-...`. Pentru 7 din cele 17
    de GHSA distincte OSV dă un alias CVE — adică se poate afla EPSS și KEV.
    Pentru celelalte 10 NU există alias, deci nici EPSS, nici KEV: exploatarea
    lor rămâne necunoscută și constatarea rămâne gri.

## De ce nu `/v1/querybatch`

Forma „în bloc" a OSV răspunde la altă întrebare: „ce vulnerabilități afectează
pachetul X la versiunea Y" (și întoarce doar id-uri). Trivy a răspuns deja la
ea. Ce ne lipsește e conținutul unui id cunoscut, iar pentru el nu există formă
în bloc; sunt câteva zeci de cereri pe zi, secvențiale și cu pauză.

Scorul numeric se calculează din vector când e v3 (`cvss.base_score`); pentru v4
rămâne `NULL` și importanța se estimează din severitate, spunând că e o estimare.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from sentinel.db.engine import Database
from sentinel.intel import mirror
from sentinel.logging_setup import get_logger
from sentinel.scan import cvss

log = get_logger(__name__)

SOURCE = "osv"
URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

FOUND_DAYS = 7.0
UNRATED_DAYS = 1.0
NOT_FOUND_DAYS = 7.0
BUDGET = 250

_SEVERITY_WORD = re.compile(r"^[A-Za-z_ ]{1,20}$")


@dataclass(frozen=True)
class Row:
    status: str
    score: float | None
    vector: str | None
    version: str | None
    severity: str | None
    aliases: tuple[str, ...]
    fetched_at: datetime | None


def valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(
        mirror.CVE_ID.match(value) or mirror.GHSA_ID.match(value))


def parse(payload: Any, requested: str) -> dict[str, Any] | None:
    """Câmpurile folosite dintr-un răspuns OSV, sau `None` dacă nu e răspunsul
    la ce s-a cerut.

    `id` trebuie să fie chiar id-ul cerut: un răspuns pentru altă vulnerabilitate
    (un redirect, o pagină de eroare cu 200) ar atribui scorul altcuiva.
    """
    if not isinstance(payload, dict) or payload.get("id") != requested:
        return None

    # V3 înaintea lui V4: pe V3 putem calcula numărul. Un V4 rămâne folosibil —
    # punctele de decizie SSVC se citesc din vector — dar fără scor.
    chosen: cvss.Vector | None = None
    sev = payload.get("severity")
    if isinstance(sev, list):
        parsed = [cvss.parse(e.get("score")) for e in sev if isinstance(e, dict)]
        usable = [v for v in parsed if v is not None]
        for wanted_prefix in ("3", "4"):
            chosen = next((v for v in usable if v.version.startswith(wanted_prefix)), None)
            if chosen is not None:
                break

    aliases: list[str] = []
    raw_aliases = payload.get("aliases")
    if isinstance(raw_aliases, list):
        for a in raw_aliases:
            if valid_id(a) and a != requested and a not in aliases:
                aliases.append(a)

    word = None
    db_specific = payload.get("database_specific")
    if isinstance(db_specific, dict):
        s = db_specific.get("severity")
        if isinstance(s, str) and _SEVERITY_WORD.match(s):
            word = s

    return {
        "cvss_score": cvss.base_score(chosen), "cvss_vector": chosen.raw if chosen else None,
        "cvss_version": chosen.version if chosen else None,
        "severity": word, "justification": None,
        "aliases": aliases[:10], "advisories": [],
    }


async def fetch_one(http: httpx.AsyncClient, vuln_id: str) -> mirror.Outcome:
    try:
        resp = await http.get(URL.format(vuln_id=vuln_id))
    except httpx.HTTPError as exc:
        return mirror.Outcome("error", error=f"{type(exc).__name__}: {exc}"[:200])
    if resp.status_code == 404:
        return mirror.Outcome("not_found", {})
    if resp.status_code != 200:
        return mirror.Outcome("error", error=f"HTTP {resp.status_code}")
    try:
        record = parse(resp.json(), vuln_id)
    except ValueError:
        record = None
    if record is None:
        return mirror.Outcome("error", error="răspuns ilizibil sau pentru alt id")
    return mirror.Outcome("found", record)


async def ensure(db: Database, ids: set[str], *, http: httpx.AsyncClient | None = None,
                 now: datetime | None = None, budget: int = BUDGET,
                 pause_s: float = mirror.PAUSE_S) -> dict[str, Any]:
    """Aduce din OSV ce lipsește sau a îmbătrânit pentru `ids`. Nu ridică."""
    try:
        wanted = {i for i in ids if valid_id(i)}
        todo = await mirror.due(db, SOURCE, wanted, found_days=FOUND_DAYS,
                                unrated_days=UNRATED_DAYS,
                                not_found_days=NOT_FOUND_DAYS, now=now)
        summary = await mirror.run_lookups(db, SOURCE, todo, fetch_one, http=http,
                                           budget=budget, pause_s=pause_s)
        summary["wanted"] = len(wanted)
        return summary
    except Exception as exc:  # noqa: BLE001 - o sursă căzută nu strică scanarea
        reason = f"{type(exc).__name__}: {exc}"[:200]
        log.warning("OSV: trecere eșuată", extra={"detail": reason})
        await mirror.record(db, SOURCE, ok=False, error=reason)
        return {"status": "failed", "error": reason}


async def load(db: Database, ids: set[str]) -> dict[str, Row]:
    if not ids:
        return {}
    rows = await db.fetch(
        """
        SELECT vuln_id, status, cvss_score, cvss_vector, cvss_version, severity,
               aliases, fetched_at
        FROM vuln_intel WHERE source = $1 AND vuln_id = ANY($2::text[])
        """,
        SOURCE, sorted(ids))
    return {r["vuln_id"]: Row(
        r["status"],
        None if r["cvss_score"] is None else float(r["cvss_score"]),
        r["cvss_vector"], r["cvss_version"], r["severity"],
        tuple(r["aliases"] or ()), r["fetched_at"]) for r in rows}
