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


#: Unde isi tine scanerul metadatele dnf.
#:
#: Creat de systemd prin `CacheDirectory=sentinel-dnf` in
#: `deploy/systemd/sentinel-scan.service`, cu proprietarul serviciului. Calea e
#: repetata aici fiindca dnf o cere ca argument, iar `test_scan_cache_dir.py`
#: cere ca cele doua sa fie ACEEASI — despartite, una s-ar muta si cealalta ar
#: scrie in continuare intr-un director pe care nimeni nu-l mai creeaza.
CACHE_DIR = "/var/cache/sentinel-dnf"

#: Cat asteptam dupa dnf.
#:
#: Masurat pe gazda reala, 21 august 2026: 7 secunde ca root (cu cache-ul
#: sistemului), 82 ca utilizatorul neprivilegiat FARA cache, 2,4 CU cache-ul lui.
#: Plafonul era 120, iar rularile reale luau intre 82 si 120 — deci in fiecare
#: noapte era o moneda aruncata, si a picat de patru ori in doua saptamani.
#:
#: Cache-ul rezolva cazul obisnuit. Plafonul de aici acopera cazul RAU care
#: ramane: prima rulare dupa ce cache-ul e sters, masurata la 87 de secunde.
#: Marginea e peste dublu, ca o gazda incarcata sa nu-l atinga.
TIMEOUT_S = 300


async def _run(argv: list[str], timeout: int = TIMEOUT_S) -> tuple[int, str, str]:
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
    # `cachedir` explicit, si nu e un reglaj de viteza — e ce tine scanarea in
    # viata. Comentariul de aici spunea pana pe 21 august 2026 ca „scanerul
    # neprivilegiat citeste cache-ul pe care sistemul il intretine deja". Nu-l
    # citeste: /var/cache/dnf apartine lui root, iar dnf rulat ca `sentinel` il
    # reconstruia in intregime la fiecare rulare. Masurat: 82 de secunde in loc
    # de 2,4, contra unui plafon de 120 — de patru ori a trecut de el si scanarea
    # a murit, lasand lista de vulnerabilitati inghetata fara ca nimeni sa afle.
    #
    # Tot fara `--refresh`: reimprospatarea ramane treaba lui `dnf-makecache`.
    # Ce se schimba e ca acum exista un cache in care sa scrie.
    rc, out, err = await _run([
        "dnf", "-q", f"--setopt=cachedir={CACHE_DIR}",
        "updateinfo", "list", "cves", "--security"])
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
