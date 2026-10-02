"""CISA Vulnrichment — punctele SSVC PUBLICATE de CISA, oglindite local.

Arborele SSVC are trei puncte pe care un vector CVSS nu le poate spune cu
adevărat: *Exploitation* (ce s-a OBSERVAT: `none` / `poc` / `active`), *Automatable*
și *Technical Impact*. Până aici le deduceam — Automatable și Technical Impact din
vector (euristici), Exploitation dintr-un prag EPSS, adică o PREVIZIUNE luată drept
OBSERVAȚIE. CISA le publică ea însăși, pentru fiecare CVE pe care l-a evaluat, în
înregistrarea CVE (containerul ADP „CISA-ADP"), fără cheie:

    https://cveawg.mitre.org/api/cve/<CVE>

```
"containers": {"adp": [{"providerMetadata": {"shortName": "CISA-ADP", ...},
  "metrics": [{"other": {"type": "ssvc", "content": {
      "timestamp": "2025-04-08T15:16:38.515188Z", "role": "CISA Coordinator",
      "version": "2.0.3", "options": [{"Exploitation": "none"},
      {"Automatable": "yes"}, {"Technical Impact": "total"}]}}}]}]}
```

## De ce serviciul CVE, per CVE, și nu o oglindă git

Aceeași înregistrare există în trei locuri: serviciul CVE (`cveawg.mitre.org`),
`CVEProject/cvelistV5` și `cisagov/vulnrichment`. Se alege UNUL, cel mai ieftin, și
nu se construiește și al doilea. Măsurat pe 2 octombrie 2026 (80 de CVE-uri ale
gazdei; un client de pe un laptop, deci cifrele de timp sunt ale rețelei de acolo):

| Cale | Cost |
|---|---|
| `cveawg.mitre.org/api/cve/<CVE>` | 19,0 s și 734 KiB pentru 80 de înregistrări (0,1 s pauză); limită declarată `25000;w=60`; zero disc |
| `raw.githubusercontent.com/.../cves/<an>/<N>xxx/<CVE>.json` | 25,7 s și 1,5 MiB pentru 80; înregistrarea întreagă (și CNA); limită nedeclarată |
| `cvelistV5`, clonă completă | 3,0 GB (mărimea raportată de GitHub); arhiva zilnică 618 MB; delta orară 0,3–0,4 MB |
| `cvelistV5`, clonă parțială (`--filter=blob:none --depth 1`) + `sparse-checkout` | gol: 9,6 MB, 5 s; cu 80 de fișiere: 50 MB, 2,4 s; apoi `fetch` + `checkout` la o zi distanță: +9,8 MB și ~17 s (un `fetch` fără nimic nou: 10–43 s); `.git` crește ~10 MB pe zi fără `gc` (~3,5 GB pe an) |

Oglinda git ar cere în plus binarul `git`, un director scriibil sub `ProtectSystem=strict`,
lista de căi menținută pe măsură ce se schimbă CVE-urile deschise, și curățenie
periodică; nu aduce nimic ce ne trebuie (CVSS vine de la Red Hat/OSV/scaner, intervalele
afectate nu se folosesc). Argumentul „oglinda merge și când rețeaua nu merge" e deja
îndeplinit: răspunsurile se scriu în tabela `vulnrichment` din Postgres, ca `kev_catalog`,
iar trecerea de evaluare citește DIN ea — un CVE deja întrebat rămâne cunoscut oricât
ar cădea rețeaua; doar un CVE nou așteaptă. Serviciul CVE întoarce EXACT același
container CISA-ADP (cu aceleași `timestamp` și `version`), deci proveniența se păstrează
întreagă: sursa e „CISA-ADP, prin înregistrarea CVE", cu momentul evaluării din
înregistrare (`ssvc_at`), nu cu ora descărcării.

## Ce înseamnă „nu avem valoare"

Trei stări, și nu sunt aceeași:

  * **niciun rând** — nu am întrebat încă (sau sursa e căzută). Necunoscut: punctul
    rămâne neluat, iar constatarea e gri;
  * **`found` fără puncte** — CVE-ul există, dar CISA nu l-a evaluat (încă). E un
    răspuns, nu o lipsă. Măsurat pe gazda de producție, 2 octombrie 2026, pe cele 406
    de CVE-uri distincte deschise: CISA a publicat puncte pentru 196 = **48,3%**, iar
    acoperirea depinde de ecosistem — npm 78/78, composer 36/36, go 45/57, alpine
    13/16, **deb 13/185 (7%)**, rpm 6/32 (19%). Pe rânduri, Exploitation vine din
    presupunerea `kev_absent` la 395 din 812 = **49%**. (Un eșantion anterior de 78 de
    CVE-uri, în mare parte npm/composer, dădea 80%: nu conținea niciunul din cele 185
    de CVE-uri Debian de nucleu. Pe un eșantion de 320 de CVE-uri Red Hat, 2019–2026,
    acoperirea e de 41%, cu 8–15% pe 2019–2021, 62–78% pe 2022–2024 și ~40% pe
    2025–2026: curba pe ani e adevărată, cifra pe gazdă nu era.);
  * **`not_found`** — 404.

## Un parser orb arată ca „CISA n-a evaluat nimic"

Dacă CISA își schimbă `orgId`, rolul sau forma `options`, fiecare răspuns devine
„found fără puncte", iar Exploitation cade tăcut pe `none`. De aceea o trecere care
primește cel puțin `CANARY_MIN` CVE-uri și NICIUN punct SSVC devine SUSPECTĂ.

**Suspectă nu înseamnă orbă.** Doar 7% dintre CVE-urile Debian de nucleu au puncte
CISA, deci un lot de 20–30 de CVE-uri noi de `linux-libc-dev` are zero puncte cu
probabilitatea 0,93^20 ≈ 23% (0,93^30 ≈ 11%), fără ca parserul să fi greșit ceva; iar
`UNENRICHED_DAYS` ar fi ținut `degraded` două zile. O alarmă care sună după
COMPOZIȚIA lotului, nu după o stricăciune, învață operatorul s-o ignore. De aceea
suspiciunea se verifică cu un CONTROL POZITIV: se cere de la serviciu, în aceeași
trecere, un CVE despre care se știe că poartă puncte (`CANARY_CONTROL_CVE`) și se
trece prin același parser.

  * controlul DĂ puncte → parserul vede formatul de azi, lotul era doar neevaluat:
    nicio alarmă (`canary = "control_ok"` în rezumat);
  * controlul vine FĂRĂ puncte → parser orb: `blind`, în `intel_state.detail`, iar
    autoverificarea o ridică;
  * controlul nu se poate citi (cerere picată, 404, răspuns ilizibil) → NU se poate
    spune nimic, și „nu se poate spune" nu e „în regulă": se marchează `blind` cu
    motivul „control indisponibil", ca o alarmă care poate fi falsă să nu fie
    înlocuită cu o tăcere care poate fi falsă.

Controlul se cere LIVE, nu din fixture: o înregistrare reținută local doar ar dovedi
că parserul încă înțelege formatul VECHI, adică exact ce nu e întrebarea. Parserul e
probat pe înregistrări reale (`tests/fixtures/intel/cveawg_*.json`), nu pe unele scrise
de mână.

Nu ridică niciodată spre apelant: o sursă căzută lasă punctele neluate, iar de acolo
iese gri, nu o scanare oprită.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from sentinel.db.engine import Database
from sentinel.intel import mirror
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

SOURCE = "vulnrichment"
URL = "https://cveawg.mitre.org/api/cve/{cve}"

#: Containerul CISA din înregistrarea CVE: `orgId` e al CISA-ADP, stabil; numele
#: scurt ar putea fi redenumit.
CISA_ADP_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
#: Rolul din `content.role`. Arborele nostru (`ssvc.py`) e „CISA Coordinator"; un
#: alt rol ar însemna alt arbore, cu alte puncte.
CISA_ROLE = "CISA Coordinator"

#: Vocabularul arborelui Coordinator. O valoare în afara lui nu se stochează.
_VOCAB: dict[str, tuple[str, frozenset[str]]] = {
    "Exploitation": ("exploitation", frozenset({"none", "poc", "active"})),
    "Automatable": ("automatable", frozenset({"yes", "no"})),
    "Technical Impact": ("technical_impact", frozenset({"partial", "total"})),
}

# --- Cât de des se reia o cerere --------------------------------------------------
# Cifrele astea sunt ALEGERI ale Sentinel (nu ale CISA): nicio sursă nu spune cât de
# des își reîmprospătează evaluările. Ele mută doar CÂT DE REPEDE ajunge la noi o
# evaluare nouă, nu ce decide arborele.
#: Un CVE evaluat: reluat săptămânal (fotografia se schimbă rar; KEV, care schimbă
#: Exploitation în `active`, vine pe alt canal, zilnic).
FOUND_DAYS = 7.0
#: Un CVE existent dar neevaluat: reluat la două zile — CISA recuperează în zile.
UNENRICHED_DAYS = 2.0
NOT_FOUND_DAYS = 7.0
#: Cereri pe trecere (hourly). Limita serviciului e de 25.000/min; pauza e
#: politețe, nu constrângere.
BUDGET = 400
PAUSE_S = 0.1
#: De la câte CVE-uri `found` într-o trecere, zero puncte SSVC fac parserul SUSPECT
#: (nu orb: vezi „Un parser orb arată ca «CISA n-a evaluat nimic»").
CANARY_MIN = 20
#: CVE-ul de control pozitiv: înregistrarea lui poartă un container CISA-ADP cu puncte
#: SSVC (Exploitation `none`, Automatable `yes`, Technical Impact `total`, evaluat la
#: 8 aprilie 2025), înregistrată în fixture-ul `cveawg_CVE-2025-29927.json`.
#: Alegerea e a Sentinel; orice CVE evaluat de CISA ar merge, iar unul vechi și stabil
#: e mai bun decât unul proaspăt, a cărui evaluare ar putea fi încă în curs.
CANARY_CONTROL_CVE = "CVE-2025-29927"


@dataclass(frozen=True)
class Row:
    status: str                       # "found" | "not_found"
    exploitation: str | None
    automatable: str | None
    technical_impact: str | None
    ssvc_at: datetime | None
    ssvc_version: str | None
    fetched_at: datetime | None

    @property
    def published(self) -> bool:
        """CISA a publicat măcar un punct pentru CVE-ul ăsta."""
        return (self.exploitation is not None or self.automatable is not None
                or self.technical_impact is not None)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    # `fromisoformat` din Python 3.10 cere exact 3 sau 6 zecimale la secunde, iar
    # un RFC 3339 valid are oricâte; fără normalizare, un `...:38.5Z` ar pierde
    # data evaluării, iar punctul ar apărea fără „evaluat la".
    text = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"),
                  value.strip().replace("Z", "+00:00"), count=1)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def parse(payload: Any) -> dict[str, Any] | None:
    """Punctele SSVC ale CISA dintr-o înregistrare CVE, sau `None` dacă răspunsul
    nu e o înregistrare CVE.

    Întoarce mereu un dict cu cele cinci chei când e o înregistrare; punctele sunt
    `None` unde CISA nu a publicat sau unde valoarea iese din vocabular. Dacă sunt
    mai multe evaluări CISA, o alege pe cea mai recentă.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("cveMetadata"), dict):
        return None
    containers = payload.get("containers")
    adp = containers.get("adp") if isinstance(containers, dict) else None
    # (moment, puncte, versiune) pentru fiecare evaluare CISA care are cel puțin
    # un punct valid.
    evaluations: list[tuple[datetime | None, dict[str, str], str | None]] = []
    for container in adp if isinstance(adp, list) else []:
        meta = container.get("providerMetadata") if isinstance(container, dict) else None
        if not isinstance(meta, dict) or meta.get("orgId") != CISA_ADP_ORG_ID:
            continue
        metrics = container.get("metrics")
        for metric in metrics if isinstance(metrics, list) else []:
            other = metric.get("other") if isinstance(metric, dict) else None
            if not isinstance(other, dict) or other.get("type") != "ssvc":
                continue
            content = other.get("content")
            if not isinstance(content, dict) or content.get("role") != CISA_ROLE:
                continue
            options = content.get("options")
            points: dict[str, str] = {}
            for option in options if isinstance(options, list) else []:
                if not isinstance(option, dict):
                    continue
                for label, value in option.items():
                    spec = _VOCAB.get(label)
                    if spec is not None and isinstance(value, str) and value in spec[1]:
                        points[spec[0]] = value
            if points:
                version = content.get("version")
                evaluations.append((_parse_time(content.get("timestamp")), points,
                                    version[:20] if isinstance(version, str) else None))
    out: dict[str, Any] = {"exploitation": None, "automatable": None,
                           "technical_impact": None, "ssvc_at": None,
                           "ssvc_version": None}
    if evaluations:
        # Cea mai recentă; una fără moment pierde în fața uneia datate, iar la
        # egalitate rămâne prima din răspuns (`max` întoarce primul maxim).
        floor = datetime.min.replace(tzinfo=timezone.utc)
        moment, points, version = max(evaluations, key=lambda ev: ev[0] or floor)
        out.update(points)
        out["ssvc_at"], out["ssvc_version"] = moment, version
    return out


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


async def _control_result(http: httpx.AsyncClient | None) -> tuple[str, str | None]:
    """Controlul pozitiv: `("points" | "blind" | "unreadable", motiv)`.

    Cere LIVE `CANARY_CONTROL_CVE` și îl trece prin `fetch_one` — același drum ca pe
    orice CVE al gazdei — fără să scrie nimic în `vulnrichment` (nu e un CVE al
    gazdei). Nu ridică.
    """
    owns = http is None
    client = http or mirror.client()
    try:
        outcome = await fetch_one(client, CANARY_CONTROL_CVE)
    except Exception as exc:  # noqa: BLE001 - controlul nu are voie să strice trecerea
        return "unreadable", f"{type(exc).__name__}: {exc}"[:120]
    finally:
        if owns:
            await client.aclose()
    if outcome.kind == "found":
        rec = outcome.record or {}
        if any(rec.get(k) is not None
               for k in ("exploitation", "automatable", "technical_impact")):
            return "points", None
        return "blind", None
    return "unreadable", (outcome.error or outcome.kind)[:120]


async def store(db: Database, cve: str, outcome: mirror.Outcome) -> None:
    """Scrie un răspuns `found` / `not_found` în `vulnrichment`.

    Un răspuns `found` FĂRĂ puncte nu șterge punctele deja stocate: CISA nu retrage
    o evaluare, deci „acum nu le văd" e mai probabil un parser sau un răspuns
    trunchiat decât o retragere, iar suprascrisă cu NULL, o evaluare bună ar
    deveni „nepublicată" tăcut.
    """
    rec = outcome.record or {}
    await db.execute(
        """
        INSERT INTO vulnrichment (cve, status, exploitation, automatable,
                                  technical_impact, ssvc_at, ssvc_version, fetched_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, now())
        ON CONFLICT (cve) DO UPDATE SET
            status = EXCLUDED.status,
            exploitation = COALESCE(EXCLUDED.exploitation, vulnrichment.exploitation),
            automatable = COALESCE(EXCLUDED.automatable, vulnrichment.automatable),
            technical_impact = COALESCE(EXCLUDED.technical_impact,
                                        vulnrichment.technical_impact),
            ssvc_at = COALESCE(EXCLUDED.ssvc_at, vulnrichment.ssvc_at),
            ssvc_version = COALESCE(EXCLUDED.ssvc_version, vulnrichment.ssvc_version),
            fetched_at = now()
        """,
        cve, outcome.kind, rec.get("exploitation"), rec.get("automatable"),
        rec.get("technical_impact"), rec.get("ssvc_at"), rec.get("ssvc_version"))


async def due(db: Database, cves: set[str], *, now: datetime | None = None) -> list[str]:
    """CVE-urile din `cves` care trebuie (re)cerute, în ordine stabilă. Lipsa
    rândului înseamnă „niciodată cerut"."""
    if not cves:
        return []
    rows = await db.fetch(
        """
        SELECT cve, status, exploitation, automatable, technical_impact, fetched_at
          FROM vulnrichment WHERE cve = ANY($1::text[])
        """, sorted(cves))
    have = {r["cve"]: r for r in rows}
    now = now or datetime.now(timezone.utc)
    out: list[str] = []
    for cve in sorted(cves):
        row = have.get(cve)
        if row is None:
            out.append(cve)
            continue
        age_days = (mirror.hours_since(row["fetched_at"], now=now) or 0.0) / 24
        if row["status"] == "not_found":
            limit = NOT_FOUND_DAYS
        elif (row["exploitation"] is None and row["automatable"] is None
              and row["technical_impact"] is None):
            limit = UNENRICHED_DAYS
        else:
            limit = FOUND_DAYS
        if age_days >= limit:
            out.append(cve)
    return out


async def ensure(db: Database, cves: set[str], *, http: httpx.AsyncClient | None = None,
                 now: datetime | None = None, budget: int = BUDGET,
                 pause_s: float = PAUSE_S) -> dict[str, Any]:
    """Aduce de la CISA ce lipsește sau a îmbătrânit pentru `cves`. Nu ridică."""
    try:
        wanted = {c for c in cves if c and mirror.CVE_ID.match(c)}
        todo = await due(db, wanted, now=now)
        seen = {"found": 0, "with_points": 0}

        async def _store(d: Database, cve: str, outcome: mirror.Outcome) -> None:
            await store(d, cve, outcome)
            if outcome.kind == "found":
                seen["found"] += 1
                rec = outcome.record or {}
                if any(rec.get(k) is not None
                       for k in ("exploitation", "automatable", "technical_impact")):
                    seen["with_points"] += 1

        summary = await mirror.run_lookups(db, SOURCE, todo, fetch_one, http=http,
                                           budget=budget, pause_s=pause_s, store=_store)
        summary["wanted"] = len(wanted)
        summary["with_points"] = seen["with_points"]
        if seen["found"] >= CANARY_MIN and seen["with_points"] == 0:
            # Suspect, nu dovedit: un lot de CVE-uri Debian de nucleu arată la fel.
            verdict, why = await _control_result(http)
            if verdict == "points":
                summary["canary"] = "control_ok"
                log.info("Vulnrichment: lot fără puncte, dar controlul pozitiv le are "
                         "(compoziția lotului, nu parser orb)",
                         extra={"detail": f"{seen['found']} CVE-uri", **summary})
            else:
                summary["blind"] = True
                summary["canary"] = ("control_blind" if verdict == "blind"
                                     else "control_unreadable")
                reason = (f"{seen['found']} CVE-uri primite și niciun punct SSVC CISA, "
                          + (f"iar CVE-ul de control {CANARY_CONTROL_CVE}, care are puncte, "
                             "vine și el fără: parserul sau forma răspunsului s-a schimbat"
                             if verdict == "blind" else
                             f"iar controlul pozitiv {CANARY_CONTROL_CVE} nu a putut fi "
                             f"citit ({why}): nu se poate spune dacă e parser orb sau doar "
                             "un lot neevaluat"))
                log.error("Vulnrichment: parser orb", extra={"detail": reason, **summary})
                await mirror.record(db, SOURCE, ok=False, error=reason,
                                    detail=dict(summary))
        return summary
    except Exception as exc:  # noqa: BLE001 - o sursă căzută nu strică scanarea
        reason = f"{type(exc).__name__}: {exc}"[:200]
        log.warning("Vulnrichment: trecere eșuată", extra={"detail": reason})
        await mirror.record(db, SOURCE, ok=False, error=reason)
        return {"status": "failed", "error": reason}


async def load(db: Database, cves: set[str]) -> dict[str, Row]:
    if not cves:
        return {}
    rows = await db.fetch(
        """
        SELECT cve, status, exploitation, automatable, technical_impact, ssvc_at,
               ssvc_version, fetched_at
          FROM vulnrichment WHERE cve = ANY($1::text[])
        """, sorted(cves))
    return {r["cve"]: Row(r["status"], r["exploitation"], r["automatable"],
                          r["technical_impact"], r["ssvc_at"], r["ssvc_version"],
                          r["fetched_at"]) for r in rows}
