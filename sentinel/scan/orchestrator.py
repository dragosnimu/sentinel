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


async def run_all(db: Database, cfg: Config, *, triggered_by: str = "schedule") -> dict[str, dict]:
    if not cfg.scan.enabled:
        return {"skipped": {"reason": "scan disabled"}}

    # Refresh the KEV mirror first so every finding this pass is scored against
    # today's exploited-in-the-wild list. Best-effort; never fails the scan.
    await kev.refresh(db)

    summary: dict[str, dict] = {}
    if cfg.scan.os_packages:
        summary["dnf"] = await _run_os_packages(db, triggered_by)
    return summary


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
