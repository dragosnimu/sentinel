"""Run the enabled scanners, enrich, prioritise, and record.

One pass = one timer firing. For each scanner: open a `scans` row, collect raw
findings, enrich each with KEV, score it, upsert (dedup by finding_key), then
mark anything the scanner used to report but no longer does as resolved. A single
scanner failing is recorded on its own row and does not stop the others.

Three scanners are wired here: `dnf` for OS packages, `trivy_fs` for the
application dependencies dnf cannot see, and `trivy_image` for what the running
containers carry. nuclei and semgrep slot into the same loop; each is one more
`_run_*` behind its config flag.

The `_run_*` bodies below have the same shape on purpose and are NOT folded into
one helper. They differ in what each scanner can prove — trivy also has to answer
for the age of its vulnerability database, and `trivy_image` has to answer for
whether there was a docker to talk to at all — and the last time this loop was
made generic, the special case was the one that mattered.
"""

from __future__ import annotations

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import findings as fx
from sentinel.intel import kev
from sentinel.logging_setup import get_logger
from sentinel.scan import announce, os_packages, prioritize, trivy_fs, trivy_image

log = get_logger(__name__)

# Plans drafted per scan pass. Each one is an Opus call, and each one that lands
# is a notification on someone's phone at 3 a.m. — both are reasons to keep this
# small. Whatever is left over is offered by the next pass.
MAX_PLANS_PER_PASS = 3


async def run_all(db: Database, cfg: Config, *, triggered_by: str = "schedule") -> dict[str, dict]:
    if not cfg.scan.enabled:
        return {"skipped": {"reason": "scan disabled"}}

    # Refresh the KEV mirror first so every finding this pass is scored against
    # today's exploited-in-the-wild list. Best-effort; never fails the scan.
    await kev.refresh(db)

    summary: dict[str, dict] = {}
    if cfg.scan.os_packages:
        summary["dnf"] = await _run_os_packages(db, triggered_by)
    if cfg.scan.filesystem:
        summary[trivy_fs.SCANNER] = await _run_trivy_fs(db, cfg, triggered_by)
    if cfg.scan.containers:
        summary[trivy_image.SCANNER] = await _run_trivy_image(db, triggered_by)

    summary["patch_plans"] = await _draft_plans(db, cfg)

    # Anuntul, la SFARSIT: dupa ce fiecare scaner si-a incheiat rularea si dupa
    # ce planurile au fost schitate. Trimis dupa fiecare scaner in parte, un
    # operator cu trei scanere ar primi trei mesaje pentru aceeasi rulare.
    #
    # Constatarile se aduna din TOATE scanerele care raporteaza `new_items`, nu
    # dintr-unul anume: un scaner adaugat maine intra in anunt fara sa editeze
    # nimeni linia asta, iar unul care nu raporteaza nimic nu strica nimic.
    fresh: list[dict] = []
    for result in summary.values():
        fresh.extend(result.get("new_items") or [])
    if fresh:
        summary["announced"] = {"chats": await announce.announce(cfg, fresh),
                                "findings": len(fresh)}
    return summary


async def _draft_plans(db: Database, cfg: Config) -> dict:
    """Draft patch plans for what the scan just found being exploited.

    This is the only place in the system that spends money without being asked,
    so it is fenced on four sides:

      * `patch.auto_generate_for_kev` — off, and nothing happens;
      * no API key — nothing happens, and the scan is unaffected;
      * only KEV findings with a known fixed version and no live plan already
        (that filter lives in `generate_for_kev`);
      * a hard cap per pass, so a scan that surfaces thirty exploited CVEs costs
        three model calls, not thirty.

    Generating is not applying. A plan is a written proposal that still needs two
    explicit taps on Telegram before anything on this machine changes.
    """
    if not cfg.patch.auto_generate_for_kev:
        return {"status": "disabled"}

    from sentinel.config import get_secrets
    api_key = get_secrets().get("ANTHROPIC_API_KEY")
    if not api_key:
        # Deterministic scanning, detection and blocking are unaffected — the
        # only thing missing is the drafting, which was always the optional half.
        log.info("plan drafting skipped: no API key")
        return {"status": "skipped", "reason": "fără cheie API"}

    try:
        from sentinel.patch import planner
        results = await planner.generate_for_kev(db, cfg, api_key,
                                                 limit=MAX_PLANS_PER_PASS)
    except Exception as exc:  # noqa: BLE001 - drafting must never fail a scan
        log.error("plan drafting crashed", extra={"detail": str(exc)})
        return {"status": "failed", "error": str(exc)[:200]}

    validated = [pid for pid, status in results if status == "validated"]
    if validated:
        # WARNING, not INFO: a plan now waiting for a human is worth a line the
        # operator will actually see in `journalctl -p warning`.
        log.warning("patch plans drafted", extra={"plans": validated})
    return {"status": "completed", "attempted": len(results),
            "validated": len(validated), "plan_ids": validated}


async def _run_os_packages(db: Database, triggered_by: str) -> dict:
    scan_id = await fx.start_scan(db, "dnf", "localhost", triggered_by=triggered_by)
    try:
        raw, error = await os_packages.scan()
        if error:
            await fx.finish_scan(db, scan_id, status="failed", error=error)
            log.error("dnf scan failed", extra={"error": error})
            return {"status": "failed", "error": error}

        cves = [f["cve"] for f in raw if f.get("cve")]
        kev_map = await kev.lookup(db, cves)

        seen: list[str] = []
        # Constatarile NOI, pastrate intregi, nu doar numarate: mesajul de pe
        # Telegram are nevoie de CVE, pachet, versiuni si de steagul KEV, iar
        # toate sunt deja in `f`. O a doua interogare care le-ar citi inapoi ar
        # putea intoarce altceva — intre timp o alta rulare poate atinge randul.
        new_items: list[dict] = []
        new = 0
        for f in raw:
            due = kev_map.get(f.get("cve", ""))
            if f.get("cve") in kev_map:
                f["kev"] = True
                f["kev_due_date"] = due
            f["scan_id"] = scan_id
            # dnf findings are host-level; exposure/criticality use host defaults.
            f["priority"] = prioritize.score(f, exposed=True, criticality=3)
            if await fx.upsert_finding(db, f):
                new += 1
                new_items.append(dict(f))
            seen.append(f["finding_key"])

        resolved = await fx.mark_resolved_absent(db, "dnf", None, seen)
        await fx.finish_scan(
            db, scan_id, status="completed", findings_count=len(raw),
            new_findings=new, resolved_findings=resolved)
        log.info("dnf scan complete",
                 extra={"findings": len(raw), "new": new, "resolved": resolved,
                        "kev": len(kev_map)})
        return {"status": "completed", "findings": len(raw), "new": new,
                "resolved": resolved, "kev": len(kev_map),
                # Lista, nu doar numarul: `run_all` o duce la anunt. Ramane in
                # sumar si cand e goala, ca apelantul sa nu trebuiasca sa
                # deosebeasca „n-a fost nimic nou" de „scanarea asta nu spune".
                "new_items": new_items}
    except Exception as exc:  # noqa: BLE001 - record and surface, do not crash the pass
        await fx.finish_scan(db, scan_id, status="failed", error=str(exc)[:500])
        log.error("dnf scan crashed", extra={"detail": str(exc)})
        return {"status": "failed", "error": str(exc)[:200]}


async def _run_trivy_fs(db: Database, cfg: Config, triggered_by: str) -> dict:
    """trivy peste caile din `scan.discovery_paths`.

    Aceeasi forma ca `_run_os_packages`, cu doua lucruri in plus, si amandoua
    exista fiindca trivy poate raspunde cu incredere si totusi gresit:

      * `db_version` se scrie pe rand la FIECARE incheiere, si pe cele esuate:
        „ce a vazut scanarea" fara „cu ce baza de date s-a uitat" e o cifra
        careia nu i se poate afla valabilitatea nici a doua zi;
      * cand scanerul intoarce o eroare nu se rezolva NIMIC. O rulare care n-a
        putut sa se uite n-are voie sa inchida o constatare — lipsa unui rezultat
        nu e un zero.
    """
    target = ",".join(cfg.scan.discovery_paths or []) or "(nicio cale configurată)"
    scan_id = await fx.start_scan(db, trivy_fs.SCANNER, target[:400],
                                  triggered_by=triggered_by)
    try:
        raw, error, facts = await trivy_fs.scan(list(cfg.scan.discovery_paths or []))
        db_version = facts.get("db_version")
        if error:
            await fx.finish_scan(db, scan_id, status="failed", error=error,
                                 db_version=db_version)
            log.error("trivy fs scan failed", extra={"error": error})
            return {"status": "failed", "error": error, "db_version": db_version}

        cves = [f["cve"] for f in raw if f.get("cve")]
        kev_map = await kev.lookup(db, cves)

        seen: list[str] = []
        new_items: list[dict] = []
        new = 0
        for f in raw:
            if f.get("cve") in kev_map:
                f["kev"] = True
                f["kev_due_date"] = kev_map.get(f["cve"])
            f["scan_id"] = scan_id
            # Aceleasi implicite ca la dnf: constatarile astea sunt pe gazda care
            # serveste siturile operatorului, deci expuse, cu criticitate neutra.
            # Legarea lor de un `asset` anume ar cere o potrivire cale->activ, si
            # una gresita ar muta o vulnerabilitate pe alt sistem.
            f["priority"] = prioritize.score(f, exposed=True, criticality=3)
            if await fx.upsert_finding(db, f):
                new += 1
                new_items.append(dict(f))
            seen.append(f["finding_key"])

        resolved = await fx.mark_resolved_absent(db, trivy_fs.SCANNER, None, seen)
        await fx.finish_scan(
            db, scan_id, status="completed", findings_count=len(raw),
            new_findings=new, resolved_findings=resolved, db_version=db_version)
        log.info("trivy fs scan complete",
                 extra={"findings": len(raw), "new": new, "resolved": resolved,
                        "kev": len(kev_map), "db_version": db_version})
        return {"status": "completed", "findings": len(raw), "new": new,
                "resolved": resolved, "kev": len(kev_map),
                "db_version": db_version, "new_items": new_items}
    except Exception as exc:  # noqa: BLE001 - record and surface, do not crash the pass
        await fx.finish_scan(db, scan_id, status="failed", error=str(exc)[:500])
        log.error("trivy fs scan crashed", extra={"detail": str(exc)})
        return {"status": "failed", "error": str(exc)[:200]}


async def _run_trivy_image(db: Database, triggered_by: str) -> dict:
    """trivy peste imaginile containerelor care ruleaza.

    Aceeasi forma ca `_run_trivy_fs`, cu o intrebare pusa INAINTE de orice
    altceva: exista docker pe gazda asta?

      * NU exista deloc — nici client, nici socket, nici `DOCKER_HOST`. Atunci nu
        se deschide niciun rand in `scans`. Statusurile disponibile sunt
        `running/completed/failed/timeout` (0029 a scos `skipped` dinadins), iar
        un rand `completed` cu zero constatari despre o scanare care n-a rulat e
        exact minciuna pe care migratia aia o previne. Nu se rezolva nimic: o
        gazda fara docker n-a dovedit ca vulnerabilitatile de ieri au disparut.
      * exista, dar nu raspunde — asta E o eroare, si primeste un rand `failed`
        cu tot cu dovada (proprietarul socketului, modul, grupurile noastre).
        Asa ajunge in `/selfcheck`, sub `scan:last:trivy_image`, ceea ce e tot
        rostul: cineva a cerut scanarea containerelor si ea nu se face.
    """
    probe = await trivy_image.probe_docker()
    if probe.state == trivy_image.DOCKER_ABSENT:
        log.info("scanarea de containere nu se aplică",
                 extra={"scanner": trivy_image.SCANNER, "detail": probe.detail})
        return {"status": "not_applicable", "docker": probe.state,
                "detail": probe.detail}

    scan_id = await fx.start_scan(db, trivy_image.SCANNER,
                                  "docker: imaginile containerelor în rulare",
                                  triggered_by=triggered_by)
    try:
        raw, error, facts = await trivy_image.scan(probe)
        db_version = facts.get("db_version")
        if error:
            await fx.finish_scan(db, scan_id, status="failed", error=error,
                                 db_version=db_version)
            log.error("trivy image scan failed",
                      extra={"error": error, "docker": facts.get("docker")})
            return {"status": "failed", "error": error, "db_version": db_version,
                    "docker": facts.get("docker")}

        cves = [f["cve"] for f in raw if f.get("cve")]
        kev_map = await kev.lookup(db, cves)

        seen: list[str] = []
        new_items: list[dict] = []
        new = 0
        for f in raw:
            if f.get("cve") in kev_map:
                f["kev"] = True
                f["kev_due_date"] = kev_map.get(f["cve"])
            f["scan_id"] = scan_id
            # Aceleasi implicite ca la celelalte doua scanere: containerele de
            # aici publica porturi catre siturile operatorului, deci expuse, cu
            # criticitate neutra. Legarea de un `asset` anume ar cere o potrivire
            # imagine->activ, iar una gresita ar muta o vulnerabilitate pe alt
            # sistem.
            f["priority"] = prioritize.score(f, exposed=True, criticality=3)
            if await fx.upsert_finding(db, f):
                new += 1
                new_items.append(dict(f))
            seen.append(f["finding_key"])

        resolved = await fx.mark_resolved_absent(db, trivy_image.SCANNER, None, seen)
        await fx.finish_scan(
            db, scan_id, status="completed", findings_count=len(raw),
            new_findings=new, resolved_findings=resolved, db_version=db_version)
        log.info("trivy image scan complete",
                 extra={"findings": len(raw), "new": new, "resolved": resolved,
                        "kev": len(kev_map), "images": facts.get("images"),
                        "containers": facts.get("containers"),
                        "db_version": db_version})
        return {"status": "completed", "findings": len(raw), "new": new,
                "resolved": resolved, "kev": len(kev_map),
                "db_version": db_version, "images": facts.get("images"),
                "containers": facts.get("containers"),
                "references": facts.get("references"), "new_items": new_items}
    except Exception as exc:  # noqa: BLE001 - record and surface, do not crash the pass
        await fx.finish_scan(db, scan_id, status="failed", error=str(exc)[:500])
        log.error("trivy image scan crashed", extra={"detail": str(exc)})
        return {"status": "failed", "error": str(exc)[:200]}
