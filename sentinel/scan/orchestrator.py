"""Run the enabled scanners, enrich, prioritise, and record.

One pass = one timer firing. For each scanner: open a `scans` row, collect raw
findings, enrich each with KEV, score it, upsert (dedup by finding_key), then
mark anything the scanner used to report but no longer does as resolved. A single
scanner failing is recorded on its own row and does not stop the others.

Only the OS-package scanner is wired here (P7.1). trivy, web checks, nuclei and
semgrep slot into the same loop; each is one more `_run_*` behind its config flag.
"""

from __future__ import annotations

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import findings as fx
from sentinel.intel import kev
from sentinel.logging_setup import get_logger
from sentinel.scan import os_packages, prioritize

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

    summary["patch_plans"] = await _draft_plans(db, cfg)
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
            seen.append(f["finding_key"])

        resolved = await fx.mark_resolved_absent(db, "dnf", None, seen)
        await fx.finish_scan(
            db, scan_id, status="completed", findings_count=len(raw),
            new_findings=new, resolved_findings=resolved)
        log.info("dnf scan complete",
                 extra={"findings": len(raw), "new": new, "resolved": resolved,
                        "kev": len(kev_map)})
        return {"status": "completed", "findings": len(raw), "new": new,
                "resolved": resolved, "kev": len(kev_map)}
    except Exception as exc:  # noqa: BLE001 - record and surface, do not crash the pass
        await fx.finish_scan(db, scan_id, status="failed", error=str(exc)[:500])
        log.error("dnf scan crashed", extra={"detail": str(exc)})
        return {"status": "failed", "error": str(exc)[:200]}
