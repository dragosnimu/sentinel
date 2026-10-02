"""Trecerea de evaluare: aduce datele de risc și recalculează semaforul tuturor
constatărilor nerezolvate.

Rulează în DOUĂ locuri, cu aceeași funcție:

  * la sfârșitul scanării (`orchestrator.run_all`), după ce scanerele și-au scris
    constatările — acolo constatările NOI primesc prima evaluare, iar mesajul
    despre ele poate purta culoarea;
  * din mentenanța orară (`maintenance_service.refresh_intel`) — ca scorurile să
    se miște când se mișcă datele (EPSS se schimbă zilnic; un CVE intră în KEV
    între două scanări), indiferent dacă scanarea de azi a rulat sau a eșuat, și
    ca prima evaluare după livrare să vină în maxim o oră, nu abia la 03:15.

Sursele au porți proprii (EPSS: o descărcare pe zi; Red Hat, OSV și CISA Vulnrichment:
doar ce lipsește sau a îmbătrânit), deci o rulare orară fără nimic nou face o interogare de citire
și zero scrieri.

## Ce scrie, și ce NU scrie

Rândurile al căror conținut de evaluare nu s-a schimbat NU se rescriu: un trigger
(`findings_set_updated_at`) ridică `updated_at` la ORICE UPDATE, iar expeditorul
către martorul extern copiază rândurile după `updated_at`. O rescriere zilnică
„pentru orice eventualitate" ar reexpedia fără rost tot ce e deschis.

`cvss` și `cvss_vector` se completează DOAR când coloanele sunt goale sau conțin
ce am scris noi (vezi `risk._scanner_candidate`): niciodată peste dovada
scanerului. `kev` nu se coboară niciodată: o evaluare nu are voie să ia înapoi ce a
spus scanerul.

## Anunțul „a devenit roșu"

Doar trecerile ÎN roșu, o singură dată pe constatare (`risk_red_announced_at`):

  * prima evaluare a unui rând (`risk_changed_at IS NULL`) e punctul de plecare,
    nu o trecere — după livrare, constatările deschise primesc culori fără ca
    cineva să primească patru mesaje despre lucruri vechi;
  * un rând NOU al scanării curente e anunțat deja de mesajul „vulnerabilități
    noi", care îi poartă și culoarea;
  * un scor care oscilează în jurul unui prag nu poate redeschide canalul: o dată
    anunțat, rândul nu mai e anunțat, oricâte ori ar coborî și ar urca;
  * revendicarea e atomică (`UPDATE ... WHERE risk_red_announced_at IS NULL
    RETURNING id`): scanarea și mentenanța pot rula în același timp fără să
    trimită mesajul de două ori. Dacă livrarea nu ajunge la niciun chat,
    revendicarea se retrage și se reîncearcă la trecerea următoare.

## Ce nu face

Nu ridică spre apelant. O sursă căzută lasă constatările fără datele ei, adică
gri; o trecere întreagă căzută lasă evaluarea de ieri (sau „gri", la un rând
niciodată evaluat) și scrie eroarea în `intel_state`, de unde o citește
autoverificarea. Nu schimbă ce se scanează.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any

from sentinel.db.engine import Database
from sentinel.db.repo import findings as fx
from sentinel.intel import epss, mirror, osv, redhat, vulnrichment
from sentinel.intel.kev import lookup as kev_lookup
from sentinel.logging_setup import get_logger
from sentinel.scan import cvss, risk

log = get_logger(__name__)

#: Implicitele pe care le primește fiecare constatare până când o potrivire
#: cale->activ există (vezi comentariile din `orchestrator`): gazda servește
#: siturile operatorului, deci expusă; criticitate neutră. **Criticitatea 3 face
#: ca toate constatările să aibă Mission = medium**, iar asta e cea mai
#: consecventă intrare din tot arborele — vezi raportul de distribuție din
#: `docs/ARHITECTURA.md`.
DEFAULT_EXPOSED = True
DEFAULT_CRITICALITY = 3

#: Stările în care o constatare mai are rost evaluată. `resolved`,
#: `accepted_risk`, `false_positive` sunt închise sau decise de un om.
ASSESSED_STATUSES = ("open", "patch_planned", "patching", "deferred")

#: Oglinda KEV mai veche de atât nu poate afirma „nu e în KEV".
_KEV_MAX_AGE_DAYS = risk.KEV_MAX_AGE_DAYS


def _as_dict(value: Any) -> dict[str, Any]:
    """`jsonb` ca dict, oricum l-ar da driverul (text sau deja decodat)."""
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, bytes)):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _canon(value: Any) -> Any:
    """Forma canonică (după un drum prin JSON) pentru comparații de egalitate."""
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _num(value: float | None, places: int) -> Decimal | None:
    """Un număr pentru o coloană `numeric`, ca `Decimal` exact. Coloanele sunt
    `numeric` (nu `real`) tocmai ca expeditorul să le poată semna: un `float` nu
    ajunge pe fir, iar aici nu trebuie să se strecoare unul pe drumul spre ele."""
    return None if value is None else Decimal(f"{value:.{places}f}")


def _close(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is None and b is None
    return abs(float(a) - float(b)) < 1e-6


async def _load_findings(db: Database) -> list[dict[str, Any]]:
    rows = await db.fetch(
        f"""
        SELECT f.id, f.finding_key, f.scanner, f.ecosystem, f.cve, f.advisory_id,
               f.package, f.severity, f.cvss, f.cvss_vector, f.epss, f.epss_percentile,
               f.kev, f.kev_due_date, f.priority, f.risk, f.risk_color,
               f.risk_decision, f.risk_score, f.risk_changed_at,
               f.risk_red_announced_at,
               {fx.pending_reboot_sql("f.")} AS fix_pending_reboot
        FROM findings f
        WHERE f.status = ANY($1::text[])
        ORDER BY f.id
        """,
        list(ASSESSED_STATUSES))
    out = []
    for r in rows:
        d = dict(r)
        d["risk"] = _as_dict(d.get("risk"))
        for key in ("cvss", "epss", "epss_percentile"):
            if d.get(key) is not None:
                d[key] = float(d[key])
        out.append(d)
    return out


async def _kev_state(db: Database, today: date) -> bool:
    """Oglinda KEV există și nu e mai veche de `_KEV_MAX_AGE_DAYS`."""
    moment = await db.fetchval("SELECT max(updated_at) FROM kev_catalog")
    age_h = mirror.hours_since(moment)
    return age_h is not None and age_h <= _KEV_MAX_AGE_DAYS * 24


def _needs_osv(row: dict[str, Any], redhat_map: dict[str, redhat.Row]) -> str | None:
    """Id-ul de cerut de la OSV pentru rândul ăsta, sau None.

    Se cere când (a) lipsește CVE-ul — avizul GHSA poate avea un alias CVE, iar de
    la el vin EPSS și KEV — sau (b) niciuna din sursele de până acum nu are un
    vector CVSS citibil pentru el.
    """
    cve, adv = row.get("cve"), row.get("advisory_id")
    if not cve:
        return adv if osv.valid_id(adv) else None
    has_vector = cvss.parse(row.get("cvss_vector")) is not None
    # Un vector scris de noi la o trecere anterioară nu e „dovada scanerului",
    # dar e tot un vector: dacă există, nu mai cerem nimic.
    if has_vector:
        return None
    if row.get("ecosystem") == "rpm":
        rh = redhat_map.get(cve)
        if rh is not None and rh.status == "found" and cvss.parse(rh.vector) is not None:
            return None
    return cve if osv.valid_id(cve) else None


async def run(db: Database, cfg: Any, *, new_keys: set[str] | None = None,
              http: Any = None, announce_fn: Any = None,
              now: datetime | None = None) -> dict[str, Any]:
    """O trecere de evaluare. Întoarce un rezumat; câmpul `assessed` e
    `{finding_key: Assessment}` pentru TOATE rândurile evaluate (nu doar cele
    schimbate), ca apelantul să poată pune culoarea pe mesajele lui.

    `new_keys`: constatările inserate de scanarea curentă (anunțate separat).
    `announce_fn`: `async (items) -> chats_delivered`; implicit `announce.announce_red`
    cu `cfg`. Parametrizat ca să se poată proba fără Telegram.
    """
    started = time.monotonic()
    now = now or datetime.now(timezone.utc)
    today = now.date()
    try:
        return await _run(db, cfg, new_keys or set(), http, announce_fn, now, today,
                          started)
    except Exception as exc:  # noqa: BLE001 - evaluarea nu are voie să strice scanarea
        reason = f"{type(exc).__name__}: {exc}"[:200]
        log.error("trecerea de evaluare a eșuat", extra={"detail": reason})
        await mirror.record(db, "risk", ok=False, error=reason)
        return {"status": "failed", "error": reason, "assessed": {}}


async def _run(db: Database, cfg: Any, new_keys: set[str], http: Any,
               announce_fn: Any, now: datetime, today: date,
               started: float) -> dict[str, Any]:
    rows = await _load_findings(db)
    intel_cfg = getattr(cfg, "intel", None)
    intel_on = bool(getattr(intel_cfg, "enabled", True))
    epss_on = intel_on and bool(getattr(intel_cfg, "epss", True))
    vr_on = intel_on and bool(getattr(intel_cfg, "vulnrichment", True))

    sources: dict[str, Any] = {}

    # --- 1. Red Hat, pentru pachetele rpm ----------------------------------------
    rpm_cves = {r["cve"] for r in rows if r.get("ecosystem") == "rpm" and r.get("cve")}
    if intel_on and rpm_cves:
        sources["redhat"] = await redhat.ensure(db, rpm_cves, http=http, now=now)
    redhat_map = await redhat.load(db, rpm_cves)

    # --- 2. OSV: ce n-are vector, și avizele fără CVE ------------------------------
    osv_ids = {i for r in rows if (i := _needs_osv(r, redhat_map))}
    if intel_on and osv_ids:
        sources["osv"] = await osv.ensure(db, osv_ids, http=http, now=now)
    # Se încarcă pentru TOATE id-urile relevante, nu doar pentru cele cerute acum:
    # un răspuns din ieri trebuie să se aplice și azi.
    osv_ask = set(osv_ids) | {r["cve"] for r in rows if r.get("cve")} \
        | {r["advisory_id"] for r in rows if r.get("advisory_id")}
    osv_map = await osv.load(db, {i for i in osv_ask if osv.valid_id(i)})

    # --- 3. CVE-urile pentru care mai cerem EPSS/KEV (inclusiv aliasurile) --------
    alias_cves: set[str] = set()
    for r in rows:
        if not r.get("cve") and r.get("advisory_id"):
            row = osv_map.get(r["advisory_id"])
            if row is not None and row.status == "found":
                alias = next((a for a in row.aliases if a.startswith("CVE-")), None)
                if alias:
                    alias_cves.add(alias)
    all_cves = {r["cve"] for r in rows if r.get("cve")} | alias_cves
    if epss_on and all_cves:
        sources["epss"] = await epss.refresh(db, all_cves, http=http, now=now)
    epss_map = await epss.load(db, all_cves)

    # --- 3b. Punctele SSVC publicate de CISA ---------------------------------------
    # Pentru aceleași CVE-uri ca EPSS/KEV (aliasurile GHSA incluse). Un rând care
    # lipsește înseamnă „nu am întrebat", nu „CISA n-a evaluat" — vezi `risk.py`.
    if vr_on and all_cves:
        sources["vulnrichment"] = await vulnrichment.ensure(db, all_cves, http=http,
                                                            now=now)
    vr_map = await vulnrichment.load(db, all_cves)

    kev_map = await kev_lookup(db, sorted(all_cves)) if all_cves else {}
    intel = risk.Intel(epss=epss_map, redhat=redhat_map, osv=osv_map, kev=kev_map,
                       vulnrichment=vr_map, kev_usable=await _kev_state(db, today),
                       today=today)

    # --- 4. Evaluarea -------------------------------------------------------------
    assessed: dict[str, risk.Assessment] = {}
    changed: list[tuple[dict[str, Any], risk.Assessment]] = []
    for row in rows:
        a = risk.assess(row, intel, exposed=DEFAULT_EXPOSED,
                        criticality=DEFAULT_CRITICALITY)
        assessed[row["finding_key"]] = a
        if _differs(row, a):
            changed.append((row, a))

    # --- 5. Scrierea (doar ce s-a schimbat) --------------------------------------
    if changed:
        async with db.transaction() as conn:
            await conn.executemany(
                """
                UPDATE findings SET
                    risk_color = $2, risk_decision = $3, risk_score = $4,
                    risk = $5::jsonb, priority = $6, epss = $7, epss_percentile = $8,
                    kev = kev OR $9::boolean,
                    kev_due_date = COALESCE($10::date, kev_due_date),
                    cvss = CASE WHEN $11::boolean THEN $12::numeric ELSE cvss END,
                    cvss_vector = CASE WHEN $11::boolean THEN $13::text ELSE cvss_vector END,
                    risk_changed_at = now()
                WHERE id = $1
                """,
                [(row["id"], a.color, a.decision, _num(a.score, 5),
                  json.dumps(a.risk, sort_keys=True), a.priority,
                  _num(a.epss, 4), _num(a.epss_percentile, 4),
                  a.kev, a.kev_due, a.write_cvss,
                  _num(a.cvss_score, 1), a.cvss_vector)
                 for row, a in changed])

    # --- 6. Anunțul trecerilor în roșu -------------------------------------------
    announced = await _announce_red(db, cfg, rows, assessed, new_keys, announce_fn)

    # --- 7. Starea trecerii --------------------------------------------------------
    by_color = Counter(a.color for a in assessed.values())
    failed_sources = {k: v for k, v in sources.items()
                      if v.get("status") == "failed" or v.get("aborted")}
    summary = {
        "status": "completed", "findings": len(rows), "changed": len(changed),
        "colors": dict(by_color), "announced_red": announced,
        "sources": sources, "seconds": round(time.monotonic() - started, 1),
    }
    # `ok` = trecerea a evaluat TOATE rândurile; nu cere ca sursele să fi răspuns
    # (o sursă căzută e în `intel_state` la numele ei, iar rândurile ei sunt gri).
    await mirror.record(db, "risk", ok=True, detail={
        k: v for k, v in summary.items() if k != "sources"} | {
        "failed_sources": sorted(failed_sources)})
    log.info("evaluare de risc încheiată",
             extra={k: v for k, v in summary.items() if k != "sources"})
    if by_color.get("grey"):
        log.warning("constatări fără date suficiente pentru o decizie (gri)",
                    extra={"grey": by_color["grey"],
                           "failed_sources": ",".join(sorted(failed_sources))})
    summary["assessed"] = assessed
    return summary


def _differs(row: dict[str, Any], a: risk.Assessment) -> bool:
    """Conținutul evaluării diferă de ce e deja în rând?"""
    if (row.get("risk_color") != a.color or row.get("risk_decision") != a.decision
            or row.get("priority") != a.priority):
        return True
    if not _close(row.get("risk_score"), a.score):
        return True
    if _canon(row.get("risk") or {}) != _canon(a.risk):
        return True
    if not _close(row.get("epss"), None if a.epss is None else round(a.epss, 4)):
        return True
    if not _close(row.get("epss_percentile"),
                  None if a.epss_percentile is None else round(a.epss_percentile, 4)):
        return True
    if a.kev and not row.get("kev"):
        return True
    if a.kev and a.kev_due is not None and row.get("kev_due_date") != a.kev_due:
        return True
    if a.write_cvss:
        if not _close(row.get("cvss"), None if a.cvss_score is None
                      else round(a.cvss_score, 1)):
            return True
        if (row.get("cvss_vector") or None) != (a.cvss_vector or None):
            return True
    return row.get("risk_changed_at") is None


async def _announce_red(db: Database, cfg: Any, rows: list[dict[str, Any]],
                        assessed: dict[str, risk.Assessment], new_keys: set[str],
                        announce_fn: Any) -> int:
    """Marchează și anunță trecerile în roșu. Întoarce câte rânduri s-au anunțat
    (cu mesaj), nu câte au fost marcate."""
    red = [r for r in rows
           if assessed[r["finding_key"]].color == "red"
           and r.get("risk_red_announced_at") is None]
    if not red:
        return 0
    silent_ids = [r["id"] for r in red
                  if r.get("risk_changed_at") is None or r["finding_key"] in new_keys]
    loud = [r for r in red if r["id"] not in set(silent_ids)]

    if silent_ids:
        await db.execute(
            "UPDATE findings SET risk_red_announced_at = now() "
            "WHERE id = ANY($1::bigint[]) AND risk_red_announced_at IS NULL "
            "AND risk_color = 'red'", silent_ids)
    if not loud:
        return 0

    claimed = await db.fetch(
        "UPDATE findings SET risk_red_announced_at = now() "
        "WHERE id = ANY($1::bigint[]) AND risk_red_announced_at IS NULL "
        "AND risk_color = 'red' RETURNING id", [r["id"] for r in loud])
    claimed_ids = {c["id"] for c in claimed}
    mine = [r for r in loud if r["id"] in claimed_ids]
    if not mine:
        return 0

    enabled = bool(getattr(getattr(cfg, "scan", None), "announce_new", True))
    if not enabled:
        # Canalul e oprit de operator: rămân marcate, ca la pornirea lui să nu
        # sosească o grămadă de „devenit roșu" despre lucruri vechi.
        return 0

    items = [_item(r, assessed[r["finding_key"]]) for r in mine]
    try:
        if announce_fn is None:
            from sentinel.scan import announce
            delivered = await announce.announce_red(cfg, items)
        else:
            delivered = await announce_fn(items)
    except Exception as exc:  # noqa: BLE001 - un anunț nu strică evaluarea
        log.error("anunțul de trecere în roșu a eșuat", extra={"detail": str(exc)[:200]})
        delivered = 0
    if not delivered:
        # Nimeni nu l-a primit: se retrage revendicarea, ca trecerea următoare
        # să reîncerce în loc să-l piardă.
        await db.execute(
            "UPDATE findings SET risk_red_announced_at = NULL "
            "WHERE id = ANY($1::bigint[])", [r["id"] for r in mine])
        return 0
    return len(mine)


def _item(row: dict[str, Any], a: risk.Assessment) -> dict[str, Any]:
    """Un rând pentru mesaj: ce trebuie ca operatorul să știe de ce e roșu."""
    return {
        "id": row["id"], "cve": row.get("cve"), "advisory_id": row.get("advisory_id"),
        "package": row.get("package"), "scanner": row.get("scanner"),
        "severity": row.get("severity"), "kev": a.kev, "risk_color": a.color,
        "priority": a.priority, "risk": a.risk, "cvss": a.cvss_score,
        "epss": a.epss, "epss_percentile": a.epss_percentile,
    }
