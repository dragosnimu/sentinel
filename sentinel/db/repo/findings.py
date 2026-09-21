"""Findings and scan runs — the durable record of what the scanners saw.

A finding is keyed by `finding_key` (a stable hash of scanner + asset + package
+ cve + location), so the same vulnerability seen on ten nightly runs is one row
whose `last_seen` moves forward, not ten rows. When a scanner completes, anything
it used to report for that (scanner, asset) but did not this time is marked
resolved — a fix landed, or the package was removed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.db.engine import Database


def finding_key(scanner: str, asset_id: int | None, package: str | None,
                cve: str | None, location: str | None) -> str:
    material = "|".join(str(x or "") for x in (scanner, asset_id, package, cve, location))
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass
class ScanRun:
    id: int
    scanner: str
    target: str
    status: str
    findings_count: int
    started_at: datetime
    finished_at: datetime | None


async def start_scan(db: Database, scanner: str, target: str, *,
                     asset_id: int | None = None, triggered_by: str = "schedule") -> int:
    return int(await db.fetchval(
        """
        INSERT INTO scans (scanner, target, asset_id, triggered_by, status)
        VALUES ($1, $2, $3, $4, 'running') RETURNING id
        """,
        scanner, target, asset_id, triggered_by))


async def finish_scan(db: Database, scan_id: int, *, status: str, findings_count: int = 0,
                      new_findings: int = 0, resolved_findings: int = 0,
                      exit_code: int | None = None, error: str | None = None,
                      db_version: str | None = None) -> None:
    await db.execute(
        """
        UPDATE scans SET status = $2, findings_count = $3, new_findings = $4,
            resolved_findings = $5, exit_code = $6, error = $7, db_version = $8,
            finished_at = now(),
            duration_ms = (extract(epoch from (now() - started_at)) * 1000)::int
        WHERE id = $1
        """,
        scan_id, status, findings_count, new_findings, resolved_findings,
        exit_code, error, db_version)


async def upsert_finding(db: Database, f: dict[str, Any]) -> bool:
    """Insert or refresh one finding. Returns True if it is newly seen (or was
    resolved and has reappeared), False if it was already open."""
    row = await db.fetchrow(
        """
        INSERT INTO findings
            (finding_key, asset_id, scanner, cve, advisory_id, title, description,
             severity, cvss, cvss_vector, epss, kev, kev_due_date, package,
             installed_version, fixed_version, location, ecosystem, priority,
             scan_id, raw)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
        ON CONFLICT (finding_key) DO UPDATE SET
            last_seen = now(),
            -- A finding that was resolved but is seen again reopens.
            status = CASE WHEN findings.status = 'resolved' THEN 'open' ELSE findings.status END,
            resolved_at = NULL,
            severity = EXCLUDED.severity, cvss = EXCLUDED.cvss, epss = EXCLUDED.epss,
            kev = EXCLUDED.kev, priority = EXCLUDED.priority,
            fixed_version = EXCLUDED.fixed_version, scan_id = EXCLUDED.scan_id,
            raw = EXCLUDED.raw
        RETURNING (xmax = 0) AS is_new, status
        """,
        f["finding_key"], f.get("asset_id"), f["scanner"], f.get("cve"),
        f.get("advisory_id"), f.get("title"), f.get("description"),
        f.get("severity", "medium"), f.get("cvss"), f.get("cvss_vector"),
        f.get("epss"), f.get("kev", False), f.get("kev_due_date"), f.get("package"),
        f.get("installed_version"), f.get("fixed_version"), f.get("location"),
        f.get("ecosystem"), f.get("priority", 0), f.get("scan_id"),
        json.dumps(f.get("raw", {})),
    )
    return bool(row["is_new"])


# The statuses a scan is allowed to close. `patching`, `accepted_risk` and
# `false_positive` are decisions somebody made; a scan does not overturn them.
_RESOLVABLE_STATUSES = "status IN ('open','patch_planned','deferred')"


def _visible_sql(sev_param: int, unscored_param: int) -> str:
    """SQL for "this run could have seen that finding", given what it asked for.

    Written once and used by both queries below, because they are two halves of
    the same statement: what a run may close, and what it left behind. Two
    hand-written copies would drift, and the drift would be silent in exactly the
    direction that matters — closing a finding nobody looked for.

    A scanner records the severity it was given (`findings.severity`) and whether
    that severity was ever scored (`raw.severity_known`, written by
    `trivy_fs.map_severity`). Both halves are needed: an unscored finding is
    parked at `medium`, so matching on `severity` alone would let a run that asked
    for UNKNOWN close the real MEDIUMs it never looked for.

    `COALESCE(... , false)`, not a bare comparison: a row whose `raw` has no
    `severity_known` key yields NULL, `NOT (… OR NULL)` is NULL, and the row
    would silently fall out of BOTH queries — neither closed nor counted, which
    is the shape of a leak rather than a decision. Missing means "not known to be
    unscored", so it is treated as scored.
    """
    return (f"(severity = ANY(${sev_param}::text[])"
            f" OR (${unscored_param}::boolean"
            f" AND COALESCE(raw->'severity_known' = 'false'::jsonb, false)))")


async def mark_resolved_absent(db: Database, scanner: str, asset_id: int | None,
                               seen_keys: list[str], *,
                               visible_severities: list[str] | None = None,
                               visible_unscored: bool = False) -> int:
    """Findings this scanner used to report for the asset but did not this run
    are resolved. Passing an empty seen list resolves them all — correct when a
    scan comes back clean.

    `visible_severities` fences that off to what the run could actually see. A
    scanner that filters at the source — `trivy_image` asks trivy for HIGH and
    above — stops reporting the severities below its floor, and "not reported"
    then covers two states that are not the same thing: fixed, and no longer
    looked for. Without the fence, raising a floor announces every finding under
    it as repaired overnight, which is a worse lie than the noise the floor was
    raised to escape.

    None (the default) means the run had no floor and may close anything, which
    is what `dnf`/`apt` do today — their source is a security advisory feed,
    not a severity argument to the scan itself, so there is no floor to fence.
    `trivy_fs` and `trivy_image` both filter at the source and both pass their
    own `visible_severities()` here.
    """
    where = ["scanner = $1 AND asset_id IS NOT DISTINCT FROM $2",
             _RESOLVABLE_STATUSES,
             "finding_key <> ALL($3::text[])"]
    args: list[Any] = [scanner, asset_id, seen_keys or [""]]
    if visible_severities is not None:
        where.append(_visible_sql(4, 5))
        args += [list(visible_severities), bool(visible_unscored)]

    rows = await db.fetch(
        f"""
        UPDATE findings SET status = 'resolved', resolved_at = now(),
            resolution = 'absent_from_latest_scan'
        WHERE {' AND '.join(where)}
        RETURNING id
        """,
        *args)
    return len(rows)


async def count_open_outside_severities(db: Database, scanner: str,
                                        asset_id: int | None, *,
                                        visible_severities: list[str],
                                        visible_unscored: bool = False) -> int:
    """How many still-open findings this scanner no longer looks for.

    The counterpart of the fence above. Those rows are protected from being
    closed, which is right — but protected and unmentioned is its own quiet lie:
    they sit on the panel looking like today's measurement while nothing has
    re-checked them since the floor moved. The caller puts the number in the
    journal at WARNING so the operator has the fact instead of having to infer it
    from a count that stopped moving.
    """
    return int(await db.fetchval(
        f"""
        SELECT count(*) FROM findings
        WHERE scanner = $1 AND asset_id IS NOT DISTINCT FROM $2
          AND {_RESOLVABLE_STATUSES}
          AND NOT {_visible_sql(3, 4)}
        """,
        scanner, asset_id, list(visible_severities), bool(visible_unscored)) or 0)


def _scanner_clause(scanners: list[str] | None, column: str,
                    args: list[Any]) -> str:
    """`AND <column> = ANY($n)` când se cere un filtru, nimic când nu se cere.

    `None` și `[]` NU înseamnă același lucru, și confuzia dintre ele e singurul
    fel în care filtrul ăsta poate minți: `None` e „fără filtru, arată tot", iar
    `[]` e „categoria asta n-are niciun scaner, deci n-are niciun rând". Un
    `if scanners:` ar fi tratat lista goală ca pe absența filtrului și ar fi
    arătat TOATE constatările sub eticheta unei categorii goale.

    `coalesce(..., '')` pe aceeași formă ca numărătoarea din
    `open_counts_by_scanner`: `scanner` e NOT NULL azi pe ambele gazde, dar
    dacă asta s-ar schimba vreodată, `scanner = ANY(ARRAY[''])` NU potrivește
    un NULL, în timp ce numărătoarea l-ar aduna la „necunoscut" — pastila ar
    spune N, iar pagina filtrată ar arăta zero. Cele două laturi se scriu la
    fel ca să nu se poată contrazice.
    """
    if scanners is None:
        return ""
    args.append(list(scanners))
    return f" AND coalesce({column}, '') = ANY(${len(args)}::text[])"


def _severity_clause(severities: list[str] | None, column: str,
                     args: list[Any]) -> str:
    """`AND <column> = ANY($n)` când se cere un filtru, nimic când nu se cere.

    Aceeași convenție ca `_scanner_clause`, din același motiv: `None` e „fără
    filtru", `[]` e „nicio severitate cerută, deci niciun rând". Un apelant
    care traduce cuvântul tastat de operator într-o listă are voie să producă
    lista goală, iar asta trebuie să însemne zero rânduri, nu toate.

    Fără `coalesce`: `severity` e `NOT NULL` cu `CHECK (severity IN
    ('info','low','medium','high','critical'))` de la migrația 0003, deci
    mulțimea valorilor e închisă și niciun rând nu poate scăpa filtrului
    printr-un NULL. `scanner` n-are constrângerea asta, de-aia acolo e nevoie
    de coalesce și aici nu.

    EXISTĂ ca filtrul să se aplice ÎNAINTE de `LIMIT`. Filtrarea în Python, pe
    rândurile deja tăiate, răspundea la „arată-mi criticele" cu „criticele
    care se întâmplă să fie în primele N după prioritate" — pe gazda de
    producție, unde primele 200 de rânduri nu conțin niciun `dnf`, cele două
    răspunsuri n-au nimic în comun.
    """
    if severities is None:
        return ""
    args.append(list(severities))
    return f" AND {column} = ANY(${len(args)}::text[])"


def _subset_clause(args: list[Any], *, prefix: str = "",
                   scanners: list[str] | None = None,
                   severities: list[str] | None = None,
                   kev_only: bool = False) -> str:
    """Filtrele opționale ale unei mulțimi de constatări deschise, într-o ordine.

    Un singur loc, fiindcă ordinea clauzelor din SQL trebuie să fie exact
    ordinea în care parametrii intră în `args`: `$1` e al primei clauze
    adăugate. Două apeluri împrăștiate într-o expresie cu `+` ar depinde de
    ordinea de evaluare a unei linii, iar o inversare ar da numerelor de
    parametru altă semnificație fără nicio eroare de sintaxă — filtrul pe
    severitate ar căuta printre numele de scanere.

    `kev_only` e boolean, nu tri-stare: „numai cele exploatate activ" e o
    întrebare pe care o pune cineva, „numai cele care NU sunt în KEV" nu e, iar
    un al treilea caz nefolosit ar fi cod pe care nu-l verifică nimic.

    Cu toate implicite întoarce `""` — aceeași interogare, caracter cu
    caracter, ca înainte de a exista filtrele astea.
    """
    clause = _scanner_clause(scanners, f"{prefix}scanner", args)
    clause += _severity_clause(severities, f"{prefix}severity", args)
    if kev_only:
        clause += f" AND {prefix}kev"
    return clause


async def open_counts(db: Database, *,
                      scanners: list[str] | None = None,
                      severities: list[str] | None = None,
                      kev_only: bool = False) -> dict[str, int]:
    """Constatările deschise pe severitate, plus `total` și `kev`.

    `scanners` restrânge numărătoarea la un subset — folosit de pagină când e
    aplicat un filtru pe categorie, ca pastilele de severitate și numitorul din
    „rândurile 1–200 din N" să descrie ACEEAȘI mulțime ca tabelul. Numărate
    global lângă un tabel filtrat, ar fi din nou cifre care nu se adună.

    `severities` și `kev_only` sunt aceeași nevoie pentru filtrele botului:
    numerele din antet trebuie să descrie mulțimea din care s-a tăiat lista de
    dedesubt. Numărate global lângă o listă filtrată pe severitate, dădeau
    „🔥 2 KEV" deasupra unei liste în care nu era niciunul.
    """
    args: list[Any] = []
    clause = _subset_clause(args, scanners=scanners, severities=severities,
                            kev_only=kev_only)
    rows = await db.fetch(
        "SELECT severity, count(*) AS n FROM findings WHERE status = 'open'"
        f"{clause} GROUP BY severity", *args)
    counts = {r["severity"]: int(r["n"]) for r in rows}
    counts["total"] = sum(counts.values())
    # `kev_only` nu se mai adaugă aici: interogarea are deja `AND kev`, iar o a
    # doua copie ar fi doar o clauză redundantă care schimbă textul SQL pe care
    # se sprijină ciotul din teste.
    kev_args: list[Any] = []
    kev_clause = _subset_clause(kev_args, scanners=scanners, severities=severities)
    counts["kev"] = int(await db.fetchval(
        f"SELECT count(*) FROM findings WHERE status = 'open' AND kev{kev_clause}",
        *kev_args) or 0)
    return counts


async def open_counts_by_scanner(db: Database) -> dict[str, int]:
    """Câte constatări deschise are fiecare scaner, peste TOATE rândurile.

    Una singură, și peste toată tabela: pagina taie la 200 de rânduri, iar pe
    gazda de producție niciunul dintre primele 200 nu e `dnf` — primul e al
    373-lea. O numărătoare pe categorii făcută din rândurile afișate ar spune
    „zero pe sistemul de operare" despre o gazdă cu 477 de constatări deschise
    pe pachetele ei.

    `scanner` e NOT NULL în schemă — verificat în `information_schema.columns`
    pe ambele gazde la 21 septembrie 2026, cu zero NULL-uri și zero șiruri
    goale. `coalesce` nu e deci o apărare împotriva datelor de azi, ci
    perechea exactă a filtrului din `_scanner_clause`: dacă o migrație ar slăbi
    coloana, cheia numărată aici și valoarea căutată acolo ar rămâne aceeași,
    în loc ca pastila să spună N și pagina filtrată să arate zero.
    """
    rows = await db.fetch(
        "SELECT coalesce(scanner, '') AS scanner, count(*) AS n "
        "FROM findings WHERE status = 'open' GROUP BY 1")
    return {str(r["scanner"]): int(r["n"]) for r in rows}


async def get_finding(db: Database, finding_id: int) -> dict[str, Any] | None:
    """Un singur finding, oricare i-ar fi starea — sau `None` dacă id-ul nu există.

    `list_open` nu poate răspunde la întrebarea asta: filtrează `status =
    'open'`, deci un finding rezolvat între timp ar ieși de acolo drept
    „inexistent". Pentru operatorul care tocmai a cerut un plan pentru el, „nu
    există" și „s-a reparat deja" sunt două fapte diferite, iar cel care cere
    planul are nevoie de al doilea, nu de primul.

    `epss` și `location` sunt în listă fiindcă detaliul din Telegram le arată:
    `epss` era deja pe ecran când rândul venea din `list_open`, iar `location`
    e ce decide, prin `scan.subject.describe`, dacă lucrul ăsta stă pe sistemul
    de operare, într-o imagine sau într-o aplicație. O coloană lipsă aici nu
    dă eroare — dă un câmp care dispare tăcut din mesaj.
    """
    row = await db.fetchrow(
        """
        SELECT f.id, f.cve, f.title, f.severity, f.cvss, f.epss, f.kev,
               f.priority, f.package, f.installed_version, f.fixed_version,
               f.location, f.ecosystem, f.scanner, f.status,
               a.name AS asset_name
        FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
        WHERE f.id = $1
        """,
        finding_id)
    return dict(row) if row else None


async def list_open(db: Database, *, limit: int = 100, offset: int = 0,
                    scanners: list[str] | None = None,
                    severities: list[str] | None = None,
                    kev_only: bool = False) -> list[dict[str, Any]]:
    """O felie din constatările deschise, în ordinea priorității.

    `scanners` e filtrul pe categorie al paginii (vezi `_scanner_clause`:
    `None` arată tot, `[]` nu arată nimic), iar `offset` e ce face ca rândul
    201 să fie accesibil. Fără el, pe gazda de producție cele 477 de constatări
    de sistem n-aveau niciun drum către ecran: toate stau sub pragul de
    prioritate al primelor 200 de rânduri.

    `severities` și `kev_only` sunt aici, în SQL, și nu la apelant, tocmai
    fiindcă `LIMIT` se aplică după `WHERE` și înaintea oricărei filtrări în
    Python. Botul tăia 200 de rânduri și abia apoi păstra criticele din ele;
    întrebarea la care răspundea nu era „care sunt criticele deschise".

    `f.id DESC` la coada ordonării nu e decor: `priority`, `severity` și
    `last_seen` se repetă pe sute de rânduri, iar o ordine parțială înseamnă că
    două pagini consecutive pot arăta același rând de două ori și-l pot sări pe
    al treilea — paginarea ar pierde exact rândurile pe care a fost adăugată să
    le arate.
    """
    args: list[Any] = []
    clause = _subset_clause(args, prefix="f.", scanners=scanners,
                            severities=severities, kev_only=kev_only)
    args.append(limit)
    limit_param = len(args)
    args.append(offset)
    offset_param = len(args)
    rows = await db.fetch(
        f"""
        SELECT f.id, f.cve, f.advisory_id, f.title, f.severity, f.cvss, f.epss,
               f.kev, f.priority, f.package, f.installed_version, f.fixed_version,
               f.scanner, f.location, f.status, f.last_seen, a.name AS asset_name
        FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
        WHERE f.status = 'open'{clause}
        ORDER BY f.priority DESC, f.severity DESC, f.last_seen DESC, f.id DESC
        LIMIT ${limit_param} OFFSET ${offset_param}
        """,
        *args)
    return [dict(r) for r in rows]
