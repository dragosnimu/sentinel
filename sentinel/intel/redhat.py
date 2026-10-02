"""Red Hat Security Data — CVSS, severitate, justificare și aviz pentru pachetele rpm.

Pe gazdele RHEL-like (AlmaLinux pe producție) `dnf updateinfo` dă CVE-ul și
severitatea avizului, dar niciun scor: 6912 de constatări `dnf`, zero cu CVSS.
Red Hat publică, pentru fiecare CVE pe care îl cunoaște, un răspuns JSON fără
cheie la

    https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json

cu `cvss3` (scor + vector), `threat_severity` (Low/Moderate/Important/Critical),
`statement` — **justificarea scrisă** a evaluării, de pildă „very unlikely to
have a production system running NetworkManager with DEBUG logs enabled" — și
`affected_release[].advisory` (RHSA-...). E sursa furnizorului: AlmaLinux
reconstruiește pachetele Red Hat, deci evaluarea Red Hat (făcută PENTRU pachetul
distribuit, nu pentru amonte) e cea care se potrivește constatării.

## De ce o cerere pe CVE și nu lista în bloc

Red Hat are și o listă (`cve.json?after=<dată>&per_page=...`), dar nu poate fi
filtrată pe o mulțime de CVE-uri (`cve=A,B` → „unpermitted parameter"), iar
rândurile ei nu poartă `statement`. Pentru a lua scorurile a 32 de CVE-uri
deschise ar trebui descărcate zeci de mii de rânduri. Cererea pe CVE se face doar
pentru ce lipsește sau a îmbătrânit (`REFRESH_*`), secvențial, cu pauză, cu plafon
pe trecere — volumul zilnic real e de ordinul zecilor. Prima umplere pentru toate
cele 1482 de CVE-uri istorice a durat 707 de secunde măsurat (0,48 s pe cerere,
cu pauză de 0,2 s); nu e nevoie de ea, fiindcă doar constatările DESCHISE se
evaluează.

`404` e un răspuns (`not_found`, reluat după `NOT_FOUND_DAYS`); orice altceva
care nu e 200 e o EROARE și nu se scrie.
"""

from __future__ import annotations

import math
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

SOURCE = "redhat"
URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"

#: Un răspuns cu scor se reia după atât (Red Hat își reevaluează CVE-urile).
FOUND_DAYS = 7.0
#: Unul FĂRĂ vector se reia zilnic: o vulnerabilitate proaspătă e evaluată în zile.
UNRATED_DAYS = 1.0
NOT_FOUND_DAYS = 7.0
#: Cereri pe trecere. 250 × ~0,5 s ≈ 2 minute în cel mai rău caz; zilnic se cer
#: doar CVE-urile noi.
BUDGET = 250

MAX_JUSTIFICATION = 600
_ADVISORY = re.compile(r"^RH[A-Z]{2}-\d{4}:\d{1,6}$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class Row:
    status: str
    score: float | None
    vector: str | None
    version: str | None
    severity: str | None
    justification: str | None
    aliases: tuple[str, ...]
    advisories: tuple[str, ...]
    fetched_at: datetime | None


def _clean_text(value: Any, limit: int) -> str | None:
    """Text dintr-un răspuns de rețea, pregătit să ajungă într-un mesaj și în
    panou: fără caractere de control, cu spațiile strânse, mărginit.

    Escaparea HTML o face locul care afișează (Jinja / `announce._esc`); aici se
    taie doar ce n-ar trebui să existe în niciun text și se pune plafon, fiindcă
    textul ăsta ajunge în `findings.risk` și pleacă mai departe la martorul
    extern.
    """
    if not isinstance(value, str):
        return None
    text = _CTRL.sub("", value)
    text = " ".join(text.split())
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def parse(payload: Any) -> dict[str, Any] | None:
    """Câmpurile pe care le folosim dintr-un răspuns Red Hat, sau `None` dacă
    răspunsul nu e un obiect JSON de CVE."""
    if not isinstance(payload, dict):
        return None
    block = payload.get("cvss3")
    score: float | None = None
    vector_text: str | None = None
    version: str | None = None
    if isinstance(block, dict):
        raw_score = block.get("cvss3_base_score")
        try:
            candidate = float(raw_score) if raw_score is not None else None
        except (TypeError, ValueError):
            candidate = None
        if candidate is not None and math.isfinite(candidate) and 0.0 <= candidate <= 10.0:
            score = round(candidate, 1)
        vec = cvss.parse(block.get("cvss3_scoring_vector"))
        if vec is not None:
            vector_text, version = vec.raw, vec.version

    severity = _clean_text(payload.get("threat_severity"), 20)

    advisories: list[str] = []
    releases = payload.get("affected_release")
    if isinstance(releases, list):
        for rel in releases:
            adv = rel.get("advisory") if isinstance(rel, dict) else None
            if isinstance(adv, str) and _ADVISORY.match(adv) and adv not in advisories:
                advisories.append(adv)
    return {
        "cvss_score": score, "cvss_vector": vector_text, "cvss_version": version,
        "severity": severity,
        "justification": _clean_text(payload.get("statement"), MAX_JUSTIFICATION),
        "aliases": [], "advisories": advisories[:10],
    }


async def fetch_one(http: httpx.AsyncClient, cve: str) -> mirror.Outcome:
    try:
        resp = await http.get(URL.format(cve=cve))
    except httpx.HTTPError as exc:
        return mirror.Outcome("error", error=f"{type(exc).__name__}: {exc}"[:200])
    if resp.status_code == 404:
        return mirror.Outcome("not_found", {})
    if resp.status_code != 200:
        return mirror.Outcome("error", error=f"HTTP {resp.status_code}")
    try:
        record = parse(resp.json())
    except ValueError:
        record = None
    if record is None:
        return mirror.Outcome("error", error="răspuns ilizibil")
    return mirror.Outcome("found", record)


async def ensure(db: Database, cves: set[str], *, http: httpx.AsyncClient | None = None,
                 now: datetime | None = None, budget: int = BUDGET,
                 pause_s: float = mirror.PAUSE_S) -> dict[str, Any]:
    """Aduce din Red Hat ce lipsește sau a îmbătrânit pentru `cves`. Nu ridică."""
    try:
        wanted = {c for c in cves if c and mirror.CVE_ID.match(c)}
        todo = await mirror.due(db, SOURCE, wanted, found_days=FOUND_DAYS,
                                unrated_days=UNRATED_DAYS,
                                not_found_days=NOT_FOUND_DAYS, now=now)
        summary = await mirror.run_lookups(db, SOURCE, todo, fetch_one, http=http,
                                           budget=budget, pause_s=pause_s)
        summary["wanted"] = len(wanted)
        return summary
    except Exception as exc:  # noqa: BLE001 - o sursă căzută nu strică scanarea
        reason = f"{type(exc).__name__}: {exc}"[:200]
        log.warning("Red Hat: trecere eșuată", extra={"detail": reason})
        await mirror.record(db, SOURCE, ok=False, error=reason)
        return {"status": "failed", "error": reason}


async def load(db: Database, cves: set[str]) -> dict[str, Row]:
    if not cves:
        return {}
    rows = await db.fetch(
        """
        SELECT vuln_id, status, cvss_score, cvss_vector, cvss_version, severity,
               justification, aliases, advisories, fetched_at
        FROM vuln_intel WHERE source = $1 AND vuln_id = ANY($2::text[])
        """,
        SOURCE, sorted(cves))
    return {r["vuln_id"]: Row(
        r["status"],
        None if r["cvss_score"] is None else float(r["cvss_score"]),
        r["cvss_vector"], r["cvss_version"], r["severity"], r["justification"],
        tuple(r["aliases"] or ()), tuple(r["advisories"] or ()), r["fetched_at"])
        for r in rows}
