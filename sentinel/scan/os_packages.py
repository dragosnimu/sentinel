"""OS package vulnerabilities via `dnf updateinfo` — authoritative on AlmaLinux.

On RHEL-family systems the vendor's own security metadata is the ground truth. It
knows about BACKPORTED fixes: a CVE patched into an older version string without
bumping the upstream version. Generic scanners (trivy fs, version-string matching)
flag those as vulnerable and generate a wall of false positives; `dnf updateinfo`
does not. This is why it is the primary OS scanner and trivy is secondary.

Read-only: it lists what security updates are AVAILABLE. It never installs
anything — applying a fix is the patch pipeline (P9), behind explicit approval.
"""

from __future__ import annotations

import asyncio
import re

from sentinel.db.repo import findings as fx
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Critical/Important/Moderate/Low from the advisory -> Sentinel severities.
_SEV = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}

# e.g. "CVE-2026-1234 Important/Sec.  openssl-libs-1:3.0.7-24.el9_5.x86_64"
_LINE = re.compile(
    r"^(?P<cve>CVE-\d{4}-\d+)\s+(?P<sev>\w+)/Sec\.\s+(?P<nvra>\S+)\s*$")


def _split_nvra(nvra: str) -> tuple[str, str]:
    """openssl-libs-1:3.0.7-24.el9_5.x86_64 -> (name, version-release).
    The available (fixed) NVRA is what the advisory updates to."""
    body = nvra.rsplit(".", 1)[0]  # drop arch
    m = re.match(r"^(?P<name>.+)-(?P<ver>[^-]+-[^-]+)$", body)
    if not m:
        return nvra, ""
    ver = m.group("ver")
    if ":" in ver:  # strip epoch on the version half
        pass
    return m.group("name"), ver


async def _run(argv: list[str], timeout: int = 120) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", "timeout"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


async def scan() -> tuple[list[dict], str | None]:
    """Return (findings, error). One finding per (CVE, package) that has a
    security update available. `error` is set only on a hard failure."""
    # No --refresh: refreshing metadata needs root; the unprivileged scanner
    # reads the cache the system already maintains. list cves gives CVE-level rows.
    rc, out, err = await _run(["dnf", "-q", "updateinfo", "list", "cves", "--security"])
    if rc not in (0, 100) and not out.strip():
        # dnf uses 100 for "updates available"; a real failure has no output.
        return [], (err.strip() or f"dnf exited {rc}")[:500]

    seen: dict[tuple[str, str], dict] = {}
    for line in out.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        cve = m.group("cve")
        severity = _SEV.get(m.group("sev").lower(), "medium")
        name, fixed = _split_nvra(m.group("nvra"))
        key = (cve, name)
        if key in seen:
            continue
        seen[key] = {
            "scanner": "dnf",
            "cve": cve,
            "title": f"{cve} în {name}",
            "severity": severity,
            "package": name,
            "fixed_version": fixed or None,
            "ecosystem": "rpm",
            "finding_key": fx.finding_key("dnf", None, name, cve, None),
            "raw": {"advisory_line": line.strip()},
        }
    log.info("dnf scan parsed", extra={"findings": len(seen)})
    return list(seen.values()), None
