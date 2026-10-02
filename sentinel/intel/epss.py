"""FIRST EPSS — fișierul zilnic, oglindit local pentru CVE-urile pe care le avem.

EPSS estimează probabilitatea ca un CVE să fie exploatat în următoarele 30 de
zile, și o percentilă (cât de sus stă față de toate celelalte). FIRST publică
fișierul întreg o dată pe zi: `epss_scores-current.csv.gz`, ~2,7 MB comprimat,
~380.000 de rânduri, `#model_version:...,score_date:...` pe prima linie.

## De ce fișierul, nu API-ul pe CVE-uri

API-ul (`api.first.org/data/v1/epss?cve=A,B,C`) acceptă mai multe CVE-uri într-o
cerere, și pentru 400 de CVE-uri ar fi mai puțini octeți decât fișierul. Dar
**taie în tăcere**: măsurat pe 2 octombrie 2026, o cerere cu 100 de CVE-uri a
întors 100 de rânduri, iar una cu 300 (URL de ~4,5 kB) a întors `HTTP 200`,
`"total":0`, `"data":[]` — fără nicio eroare. Un rezultat gol care arată exact ca
„niciunul n-are scor". Fișierul n-are limita asta, e o singură cerere, și e
forma pe care FIRST o recomandă pentru volum.

Se păstrează doar rândurile CVE-urilor cerute (câteva sute, nu 380.000): o
tabelă de 380.000 de rânduri rescrisă zilnic ar fi bloat pe un Postgres care
servește și altceva. Un CVE cerut dar absent din fișier se scrie cu `epss` NULL
— e un răspuns („EPSS nu-l cunoaște încă"; CVE-urile din ultimele zile lipsesc),
iar fără el fiecare trecere ar descărca din nou fișierul pentru el.

## Un fișier pe care nu-l putem verifica nu se scrie

Descărcarea poate veni trunchiată, cu alt format sau goală. Se refuză întreagă
(și nu se scrie nimic) când: gzip-ul nu se termină, antetul `score_date` lipsește,
antetul de coloane s-a schimbat, sub `MIN_ROWS` rânduri valide, sau prea multe
rânduri ilizibile. Valorile vechi rămân, vechi, iar `intel_state` spune că
încercarea a eșuat.

Nu ridică niciodată spre apelant.
"""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

import httpx

from sentinel.db.engine import Database
from sentinel.intel import mirror
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

SOURCE = "epss"
URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

#: O valoare mai veche decât atât nu mai e o măsurătoare. FIRST publică zilnic,
#: deci șapte zile fără reîmprospătare înseamnă o oglindă stricată; `risk.py`
#: trece atunci exploatarea în „necunoscut" (gri), nu rămâne la ultima valoare.
MAX_AGE_DAYS = 7

#: Fișierul se reia dacă cea mai recentă descărcare reușită e mai veche de atât.
REFRESH_AFTER_H = 20.0
#: După o încercare, nu se mai încearcă mai devreme de atât — rulează din oră în
#: oră (mentenanța), iar o sursă căzută n-are de ce să fie bătută de 24 de ori.
RETRY_AFTER_H = 1.0
#: Un CVE nou apărut face descărcarea să se repete, dar nu mai des de atât.
MISSING_RETRY_H = 6.0

MAX_COMPRESSED = 25 * 1024 * 1024
MAX_TEXT = 120 * 1024 * 1024
#: Fișierul real are ~380.000 de rânduri (1 octombrie 2026). Sub un sfert din el
#: e o descărcare trunchiată sau o altă pagină, nu un EPSS.
MIN_ROWS = 100_000
MAX_BAD_ROWS = 100

_SCORE_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,19}$")


@dataclass(frozen=True)
class Row:
    epss: float | None
    percentile: float | None
    score_date: date | None

    def age_days(self, today: date) -> int | None:
        return None if self.score_date is None else (today - self.score_date).days


class FileRejected(ValueError):
    """Fișierul nu se poate folosi; mesajul spune de ce."""


def parse(blob: bytes, wanted: set[str]) -> tuple[date, dict[str, tuple[float, float]], int]:
    """`(score_date, {cve: (epss, percentile)}, rânduri_valide)` pentru `wanted`.

    Funcție PURĂ, probată pe fișiere reale mărunțite. Ridică `FileRejected`
    pentru tot ce ar face din „am citit fișierul" o afirmație neadevărată.
    """
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        text = decomp.decompress(blob, MAX_TEXT + 1)
    except zlib.error as exc:
        raise FileRejected(f"gzip stricat: {exc}") from exc
    if len(text) > MAX_TEXT:
        raise FileRejected("fișier decomprimat peste plafon")
    if not decomp.eof:
        # Un gzip tăiat la jumătate decomprimă „frumos" până unde a ajuns.
        raise FileRejected("gzip neterminat (descărcare trunchiată)")

    lines = text.decode("utf-8", errors="replace").splitlines()
    if len(lines) < 3 or not lines[0].startswith("#"):
        raise FileRejected("fără linia de antet cu score_date")
    m = _SCORE_DATE.search(lines[0])
    if not m:
        raise FileRejected("linia de antet nu conține score_date")
    try:
        score_date = date.fromisoformat(m.group(1))
    except ValueError as exc:
        raise FileRejected(f"score_date ilizibil: {m.group(1)!r}") from exc
    if lines[1].strip() != "cve,epss,percentile":
        raise FileRejected(f"antet de coloane neașteptat: {lines[1][:60]!r}")

    found: dict[str, tuple[float, float]] = {}
    valid = bad = 0
    for line in lines[2:]:
        parts = line.split(",")
        if len(parts) != 3 or not _CVE.match(parts[0]):
            bad += 1
            continue
        try:
            epss, pct = float(parts[1]), float(parts[2])
        except ValueError:
            bad += 1
            continue
        if not (0.0 <= epss <= 1.0 and 0.0 <= pct <= 1.0):
            bad += 1
            continue
        valid += 1
        if parts[0] in wanted:
            found[parts[0]] = (epss, pct)
    if bad > MAX_BAD_ROWS:
        raise FileRejected(f"{bad} rânduri ilizibile")
    if valid < MIN_ROWS:
        raise FileRejected(f"doar {valid} rânduri valide (minim {MIN_ROWS})")
    return score_date, found, valid


async def _download(http: httpx.AsyncClient) -> bytes:
    buf = bytearray()
    async with http.stream("GET", URL) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes():
            buf += chunk
            if len(buf) > MAX_COMPRESSED:
                raise FileRejected("descărcare peste plafon")
    return bytes(buf)


async def refresh(db: Database, cves: set[str], *, force: bool = False,
                  http: httpx.AsyncClient | None = None,
                  now: datetime | None = None) -> dict[str, Any]:
    """Aduce oglinda la zi pentru `cves`, dacă trebuie. Niciodată nu ridică.

    Întoarce un rezumat (`status`: `fresh` / `updated` / `failed` / `skipped`).
    Se descarcă doar dacă oglinda e veche SAU lipsește un CVE cerut, și nu mai
    des de `RETRY_AFTER_H` / `MISSING_RETRY_H` — vezi constantele.
    """
    wanted = {c for c in cves if c and _CVE.match(c)}
    now = now or datetime.now(timezone.utc)
    try:
        st = await mirror.state(db, SOURCE)
        ok_age = mirror.hours_since(st["last_ok_at"] if st else None, now=now)
        try_age = mirror.hours_since(st["last_attempt_at"] if st else None, now=now)

        have: set[str] = set()
        if wanted:
            rows = await db.fetch(
                "SELECT cve FROM epss_scores WHERE cve = ANY($1::text[])", sorted(wanted))
            have = {r["cve"] for r in rows}
        missing = wanted - have

        stale = ok_age is None or ok_age >= REFRESH_AFTER_H
        if not force:
            if not stale and not missing:
                return {"status": "fresh", "age_h": round(ok_age or 0, 1)}
            if try_age is not None:
                cooldown = RETRY_AFTER_H if stale else MISSING_RETRY_H
                if try_age < cooldown:
                    return {"status": "skipped", "reason": "încercare recentă",
                            "age_h": None if ok_age is None else round(ok_age, 1)}
        if not wanted:
            return {"status": "fresh", "reason": "niciun CVE de oglindit"}

        owns = http is None
        http = http or mirror.client()
        try:
            blob = await _download(http)
        finally:
            if owns:
                await http.aclose()
        score_date, found, valid = parse(blob, wanted)
        batch: list[tuple[Any, ...]] = []
        for cve in sorted(wanted):
            hit = found.get(cve)
            batch.append((cve, hit[0] if hit else None, hit[1] if hit else None,
                          score_date))
        await db.executemany(
            """
            INSERT INTO epss_scores (cve, epss, percentile, score_date, fetched_at)
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (cve) DO UPDATE SET
                epss = EXCLUDED.epss, percentile = EXCLUDED.percentile,
                score_date = EXCLUDED.score_date, fetched_at = now()
            """,
            batch)
        detail = {"score_date": score_date.isoformat(), "file_rows": valid,
                  "mirrored": len(batch), "absent": len(batch) - len(found)}
        await mirror.record(db, SOURCE, ok=True, detail=detail)
        log.info("EPSS oglindit", extra=detail)
        return {"status": "updated", **detail}
    except Exception as exc:  # noqa: BLE001 - o sursă căzută nu strică scanarea
        reason = f"{type(exc).__name__}: {exc}"[:200]
        log.warning("EPSS nu s-a putut reîmprospăta", extra={"detail": reason})
        await mirror.record(db, SOURCE, ok=False, error=reason)
        return {"status": "failed", "error": reason}


async def load(db: Database, cves: set[str]) -> dict[str, Row]:
    """Rândurile oglinzii pentru `cves`. Un CVE fără rând nu e în rezultat."""
    if not cves:
        return {}
    rows = await db.fetch(
        "SELECT cve, epss, percentile, score_date FROM epss_scores "
        "WHERE cve = ANY($1::text[])", sorted(cves))
    return {r["cve"]: Row(
        None if r["epss"] is None else float(r["epss"]),
        None if r["percentile"] is None else float(r["percentile"]),
        r["score_date"]) for r in rows}


def is_fresh(row: Row | None, today: date) -> bool:
    """O valoare folosibilă: există, nu e NULL, nu e mai veche de `MAX_AGE_DAYS`."""
    if row is None or row.epss is None or row.score_date is None:
        return False
    age = row.age_days(today)
    return age is not None and age <= MAX_AGE_DAYS
