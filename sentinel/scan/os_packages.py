"""OS package vulnerabilities, one backend per platform family.

The backend is chosen from `platform.family` in the configuration — the value
`deploy/lib/distro.sh` detected at install time. Nothing here reads
/etc/os-release: a second detector is a second source of truth, and the two only
ever disagree on the host where it matters.

    rhel    `dnf updateinfo list cves --security`    CVE-level, vendor-authoritative
    debian  `apt-get -s dist-upgrade`                package-level, NO CVE

**The two families do not give the same quality of answer, and this module does
not pretend otherwise.**

On RHEL-family systems the vendor's own security metadata is the ground truth.
It knows about BACKPORTED fixes: a CVE patched into an older version string
without bumping the upstream version. Generic scanners (trivy fs, version-string
matching) flag those as vulnerable and generate a wall of false positives; `dnf
updateinfo` does not. This is why it is the primary OS scanner on that family and
`trivy_fs` is pointed at the application dependencies instead.

On Debian and Ubuntu there is no equivalent. `apt` carries no CVE and no
severity — the security metadata lives in Ubuntu's OVAL feed and Debian's
security tracker, both of which are network services and neither of which is on
the host. What apt *can* answer, offline and authoritatively, is a narrower
question: **which installed packages have an update waiting in the vendor's
security pocket** (`noble-security`, `bookworm-security`, the Ubuntu Pro ESM
pockets). That is an actionable fact and it is what the debian backend reports.

So a debian finding says "there is a pending security update for openssl". It
does NOT say "openssl has CVE-2026-1234". Its `cve` is null, its severity is a
placeholder that says so in its own description, and no patch plan is drafted for
it: `patch.planner.generate_for_kev` selects on `findings.kev`, and `kev` is only
ever set for a CVE that matched the KEV mirror. No CVE, no KEV, no plan — the
patch path fails closed without a rule of its own.

Severity follows the convention `trivy_fs.map_severity` already uses for
`UNKNOWN`: `medium` with `raw.severity_known = False`, never `info`. `info` is an
assertion — "we looked, it is negligible" — while a missing severity is the
absence of one, and putting the two in the same bucket hides everything nobody
has graded yet under every triage filter.

A scan that reports less than it knows is better than one that looks complete.
Closing this gap needs a CVE data source for deb packages on the host, which is a
mechanism and an operator decision, not a line of code here.

## Absence of a finding is never reported as a clean host

Every backend distinguishes three outcomes, and the caller records all three —
the same contract `trivy_fs` and `trivy_image` return:

    findings, error=None   the scanner looked and this is what it saw
    [],       error=None   the scanner looked and there was nothing
    [],       error="..."  the scanner could NOT look — NOT the same as clean

The third one is the reason this file has its current shape. Before it, an Ubuntu
host ran `dnf`, got FileNotFoundError, the orchestrator logged it and carried on,
and the dashboard showed zero vulnerabilities. The debian backend refuses to
report a clean zero when it cannot prove it looked: no package indexes at all, no
security index among them, or output whose `Inst` lines it cannot parse are
errors, not "nothing found".

The third member of the tuple is `facts`, exactly as in `trivy_fs.scan`: it
carries `db_version` even on the error paths, so the `failed` row in `scans` says
what metadata the answer was — or was not — drawn from.

Read-only throughout: this lists what security updates are AVAILABLE. It never
installs anything — applying a fix is the patch pipeline (P9), behind explicit
approval.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from sentinel.db.repo import findings as fx
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# The scanner name is what `scans.scanner`, `findings.scanner` and every
# per-scanner selfcheck key are keyed on, so it has to be resolvable BEFORE the
# scan runs — the scans row is opened first, precisely so that a scanner which
# then dies leaves a row behind instead of silence.
#
# `rhel` must keep mapping to "dnf". `check_last_scan` reports under
# `scan:last:{scanner}`, and `selfcheck_state` on the production host has carried
# `scan:last:dnf` since 21 August 2026. Renaming it would leave the old key to be
# reconciled away and insert a new one with `since = now()`, throwing away the
# history the operator reads — the same trap `audit:records` hit.
SCANNER_BY_FAMILY: Final[dict[str, str]] = {"rhel": "dnf", "debian": "apt"}

# Used only when the family is not one we know. It gets its own name rather than
# borrowing "dnf" or "apt": that row is not a dnf result and not an apt result,
# it is the record of a scan that could not be dispatched at all.
UNKNOWN_SCANNER: Final[str] = "os_packages"


def scanner_for(family: str) -> str:
    """The scanner name this family will run under. Never raises: the caller
    needs a name for the `scans` row even when the family is nonsense."""
    return SCANNER_BY_FAMILY.get(family, UNKNOWN_SCANNER)


#: Unde isi tine scanerul dnf metadatele.
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

#: Cat asteptam dupa `apt-get -s dist-upgrade`.
#:
#: NEMASURAT pe o gazda reala — nu avem una, si asta se scrie aici, nu se
#: ascunde. Numarul nu e o masuratoare deghizata in constanta.
#:
#: Ce se stie: `apt-get -s` nu atinge reteaua, nu descarca nimic si nu
#: reconstruieste niciun cache — citeste /var/lib/dpkg si indexurile deja aduse.
#: Deci nu are cazul rau al lui dnf, cel de 87 de secunde pentru care plafonul de
#: acolo are 300. Plafonul de aici e ca sa prinda un proces ATARNAT (o
#: incuietoare tinuta de `unattended-upgrade`, un disc care nu raspunde), nu ca sa
#: margineasca o rulare normala.
#:
#: Deosebit de al lui dnf dinadins, chiar daca amandoua ar fi incaput sub acelasi
#: numar: doua plafoane scrise cu aceeasi cifra nu se pot deosebi in nicio proba,
#: iar atunci un apel care ia plafonul celuilalt trece neobservat.
APT_TIMEOUT_S = 180

#: Cel mai rau caz al modulului, pentru bugetul unitatii.
#:
#: Pe o gazda ruleaza O SINGURA familie, deci costul modulului e plafonul
#: backendului ei, nu suma celor doua. Maximul e cifra care trebuie sa incapa in
#: `TimeoutStartSec` oricare ar fi gazda; derivata, nu scrisa a doua oara, ca
#: ridicarea unuia dintre plafoane sa nu treaca pe langa testul care leaga suma
#: scanerelor de bugetul unitatii
#: (`test_scan_trivy_fs.py::test_the_measured_ceiling_fits_inside_the_unit_budget`).
WORST_CASE_TIMEOUT_S = max(TIMEOUT_S, APT_TIMEOUT_S)


async def _run(argv: list[str], timeout: int,
               env: dict[str, str] | None = None) -> tuple[int, str, str]:
    """O comanda cu un plafon EXPLICIT de asteptare.

    `timeout` n-are implicit dinadins, exact ca la `trivy_fs._run`. Cat asteptam
    depinde de ce rulam, iar un implicit egal cu bugetul unui backend e chiar
    felul in care plafonul „pe rulare" ajunge sa se aplice pe fiecare apel in
    parte. Aici sunt doua backend-uri cu doua plafoane; unul dintre ele scris ca
    implicit ar fi tacut mostenit de celalalt.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=env)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", "timeout"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def _facts(family: str, **extra: Any) -> dict[str, Any]:
    """The third member of the result tuple, seeded the same way on every path.

    `db_version` is present even when it is None, so the caller can write it onto
    a `failed` row without asking whether the key exists — a `scans` row that says
    what it saw but not what it looked with is a number nobody can date later.
    """
    return {"scanner": scanner_for(family), "family": family,
            "db_version": None, **extra}


async def scan(family: str) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    """Run the OS-package scanner for this platform family.

    Returns (findings, error, facts), the contract `trivy_fs.scan` and
    `trivy_image.scan` already use.
    """
    if family == "rhel":
        return await _scan_dnf()
    if family == "debian":
        return await _scan_apt()
    return [], (
        f"platform.family={family!r} nu are un scaner de pachete. "
        "Familii cunoscute: rhel, debian. Scanarea de pachete de sistem "
        "NU a rulat — panoul nu are date, nu are zero vulnerabilități."
    ), _facts(family)


# ===========================================================================
# rhel — dnf updateinfo
# ===========================================================================
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


async def _scan_dnf() -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    """One finding per (CVE, package) that has a security update available."""
    facts = _facts("rhel")
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
        "updateinfo", "list", "cves", "--security"], timeout=TIMEOUT_S)
    if rc not in (0, 100) and not out.strip():
        # dnf uses 100 for "updates available"; a real failure has no output.
        return [], (err.strip() or f"dnf exited {rc}")[:500], facts

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
    return list(seen.values()), None, facts


# ===========================================================================
# debian — apt security pocket
# ===========================================================================
# Where apt keeps the downloaded repository indexes. Their existence is the only
# offline proof that `apt-get update` has ever run here; without them apt-get
# answers "0 upgraded" with a straight face, which is the silent zero this whole
# module is written against.
APT_LISTS_DIR: Final[Path] = Path("/var/lib/apt/lists")

# Beyond this the index is old enough that a clean answer means little. Not an
# error — we did look, and what we saw is real — but the age travels to the
# `scans` row so the operator is not shown a fresh-looking clean report.
APT_LISTS_STALE_DAYS: Final[int] = 7

# `apt-get -s` prints one of these per package it would install or upgrade:
#
#   Inst libssl3 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, \
#        Ubuntu:24.04/noble-security [amd64])
#   Inst linux-headers-6.8.0-45 (6.8.0-45.45 Ubuntu:24.04/noble-security [amd64])
#
# The bracketed part is the currently installed version and is absent for a
# package that would be newly installed. Chosen over `apt list --upgradable`,
# which prints "WARNING: apt does not have a stable CLI interface" about itself
# and means it — and over `apt-get -s upgrade`, which hides the updates that need
# a new dependency, i.e. every kernel.
#
# NOT VERIFIED against a real Ubuntu or Debian host: nothing in this repository's
# test environment runs apt. What is pinned below is the shape apt's own
# `pkgSimulate::Describe` produces. `_read_inst_lines` is the guard for being
# wrong about it — a line that starts with `Inst` and does not match here fails
# the scan instead of being skipped, because a dropped `Inst` line is a security
# update nobody is told about.
_APT_INST = re.compile(
    r"^Inst\s+(?P<name>\S+)\s+(?:\[(?P<installed>[^\]]*)\]\s+)?\((?P<body>.+)\)\s*$")

# Every line the parser is answerable for. Kept separate from `_APT_INST` so that
# "this is an Inst line" and "we understood it" are two different questions.
_APT_INST_ANY = re.compile(r"^Inst\s")

# The vendor security pockets, as they appear in the origin field above:
# Ubuntu "noble-security", Debian "Debian-Security:12/stable-security", the
# Ubuntu Pro pockets "noble-infra-security" / "noble-apps-security". Matching
# the substring covers all of them and any mirror that keeps the pocket name,
# which every mirror does — the pocket name is part of the repository layout.
#
# Also NOT VERIFIED on a real host: neither the exact pocket names nor the
# contents of /var/lib/apt/lists have been read from one.
_SECURITY_POCKET = "security"


def _apt_index_state() -> tuple[int, int, datetime | None, str | None]:
    """(total indexes, security indexes, newest mtime, error).

    Reading a directory rather than asking apt: this has to answer "has apt ever
    fetched anything" even when apt itself would happily answer "nothing to
    upgrade". An unreadable directory is an error, not an empty result — the
    check cannot look, which is not the same as finding nothing.
    """
    try:
        entries = [p for p in APT_LISTS_DIR.iterdir() if "_Packages" in p.name]
    except FileNotFoundError:
        return 0, 0, None, (
            f"{APT_LISTS_DIR} nu există. apt nu are indexuri de pachete pe "
            "gazda asta, deci un raport fără actualizări ar fi o presupunere, "
            "nu o constatare.")
    except OSError as exc:
        return 0, 0, None, (
            f"{APT_LISTS_DIR} nu poate fi citit ({exc.strerror}). Scanarea nu "
            "poate distinge o gazdă curată de una necitită.")

    newest: datetime | None = None
    security = 0
    for p in entries:
        if _SECURITY_POCKET in p.name.lower():
            security += 1
        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
        except OSError:
            continue
        if newest is None or mtime > newest:
            newest = mtime
    return len(entries), security, newest, None


def _split_apt_body(body: str) -> tuple[str, str, str]:
    """"3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64]"
    -> ("3.0.13-0ubuntu3.5", "Ubuntu:24.04/noble-security", "amd64")

    The architecture is stripped first and from the END, because an origin can
    itself contain brackets in principle and the arch never can.
    """
    arch = ""
    m = re.search(r"\[([^\[\]]*)\]\s*$", body)
    if m:
        arch = m.group(1)
        body = body[:m.start()].strip()
    candidate, _, origins = body.partition(" ")
    return candidate.strip(), origins.strip(), arch


def _read_inst_lines(out: str) -> tuple[list[tuple[str, re.Match[str]]], str | None]:
    """Every `Inst` line, parsed — or an error naming why the list is not whole.

    Two refusals, and both exist because the alternative is a shorter list that
    looks like a healthier host. `mark_resolved_absent` runs on whatever comes
    back, so a line silently skipped here does not merely go unreported: it
    closes the finding that line used to produce.

      * an `Inst` line the expression does not match. apt's simulation format is
        pinned from its source, not from a host we can run — so being wrong about
        it is a real possibility, and the way to survive being wrong is to fail
        loudly rather than to drop the line;
      * `Inst` lines that match but carry no origin field at all. The origin is
        the ONLY thing that separates a security update from an ordinary one. If
        not one line has it, the filter below would keep nothing and the scan
        would report a clean host — the exact shape of the bug this module was
        rewritten for.

    One line without an origin among others that have it is not an error: apt
    prints an empty origin for a version with no source (a locally installed
    .deb), and such a package genuinely is not in the security pocket.
    """
    parsed: list[tuple[str, re.Match[str]]] = []
    unmatched: list[str] = []
    with_origin = 0
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not _APT_INST_ANY.match(line):
            continue
        m = _APT_INST.match(line)
        if not m:
            unmatched.append(line)
            continue
        if _split_apt_body(m.group("body"))[1]:
            with_origin += 1
        parsed.append((line, m))

    if unmatched:
        return [], (
            f"{len(unmatched)} din {len(unmatched) + len(parsed)} linii `Inst` "
            f"din ieșirea apt nu au forma așteptată, deci nu pot spune dacă "
            f"actualizările lor sunt de securitate. Prima: {unmatched[0][:200]}")
    if parsed and with_origin == 0:
        return [], (
            f"niciuna dintre cele {len(parsed)} linii `Inst` nu poartă câmpul de "
            "origine, iar el e singurul lucru care deosebește o actualizare de "
            "securitate de una obișnuită. O listă goală de constatări aici ar fi "
            "fost citită drept gazdă curată.")
    return parsed, None


async def _scan_apt() -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    """One finding per package with an update waiting in a security pocket.

    No CVE and no severity: apt does not carry either. See the module docstring
    for what that costs and what would be needed to close it.
    """
    facts = _facts("debian")
    if shutil.which("apt-get") is None:
        return [], ("apt-get nu există pe gazdă, deși platform.family=debian. "
                    "Scanarea de pachete de sistem NU a rulat."), facts

    total, security_indexes, newest, err = _apt_index_state()
    if err:
        return [], err[:500], facts
    if total == 0:
        return [], (f"{APT_LISTS_DIR} nu conține niciun index de pachete — "
                    "`apt-get update` nu a rulat niciodată aici. Un raport curat "
                    "de la apt în starea asta nu înseamnă nimic."), facts
    if security_indexes == 0:
        # Every default sources.list on Debian and Ubuntu carries the security
        # pocket. Its absence means this host does not receive security updates
        # at all — which is a far worse finding than any package this scan could
        # have produced, and reporting zero findings would have hidden it.
        return [], (f"niciun index de securitate în {APT_LISTS_DIR} din {total} "
                    "indexuri: depozitul de securitate al distribuției nu e "
                    "configurat. Gazda nu primește actualizări de securitate."), facts

    db_version = (f"apt-lists {newest.isoformat(timespec='seconds')}"
                  if newest else "apt-lists ?")
    if newest is not None:
        age_days = (datetime.now(timezone.utc) - newest).days
        if age_days >= APT_LISTS_STALE_DAYS:
            db_version = f"{db_version} (vechi de {age_days} zile)"
            log.warning("apt package indexes are stale",
                        extra={"age_days": age_days, "indexes": total})
    # Onto `facts` BEFORE the command runs, so the `failed` row below carries it
    # too: what a scan looked with is worth as much on the run that broke.
    facts["db_version"] = db_version

    # LC_ALL=C so the output cannot arrive translated, and NoLocking because the
    # scanner runs unprivileged and must never contend for apt's lock with a
    # real upgrade. `-s` simulates: nothing is downloaded, nothing is installed.
    env = {**os.environ, "LC_ALL": "C", "LANG": "C",
           "DEBIAN_FRONTEND": "noninteractive"}
    rc, out, err_out = await _run(
        ["apt-get", "-s", "-q", "-o", "Debug::NoLocking=true", "dist-upgrade"],
        timeout=APT_TIMEOUT_S, env=env)
    if rc != 0:
        # apt-get uses 100 for every error, unlike dnf where 100 means "updates
        # available". A non-zero exit here is a failure with no usable output.
        return [], (err_out.strip() or out.strip()
                    or f"apt-get exited {rc}")[:500], facts

    lines, parse_error = _read_inst_lines(out)
    if parse_error:
        return [], parse_error[:500], facts

    seen: dict[str, dict] = {}
    for line, m in lines:
        name = m.group("name")
        candidate, origins, arch = _split_apt_body(m.group("body"))
        if _SECURITY_POCKET not in origins.lower():
            continue    # an ordinary update, not a security one
        if name in seen:
            continue
        seen[name] = {
            "scanner": "apt",
            # Deliberately null. There is no CVE in apt's metadata, and inventing
            # one — or leaving the field to be filled by a guess later — is how a
            # "vulnerability" appears that nobody can look up. It is also what
            # keeps this off the patch path: no CVE, no KEV match, no plan.
            "cve": None,
            "title": f"Actualizare de securitate disponibilă: {name}",
            "description": (
                f"Pachetul {name} are o actualizare în depozitul de securitate "
                f"({origins}). apt nu publică CVE sau severitate per pachet, "
                "deci Sentinel nu le poate afla de pe gazdă: severitatea de mai "
                "sus este o valoare implicită, NU o evaluare. Ce se știe sigur "
                "este că furnizorul a publicat această actualizare ca fiind de "
                "securitate."),
            # `medium` with `severity_known: False`, the same pair
            # `trivy_fs.map_severity` returns for `UNKNOWN`. The database CHECK
            # allows only info/low/medium/high/critical, so there is no way to
            # store "unknown"; the description above and the flag in `raw` carry
            # it instead. Not `info`: that is an assertion of harmlessness, and
            # everything ungraded would disappear under every triage filter.
            "severity": "medium",
            "package": name,
            "installed_version": m.group("installed") or None,
            "fixed_version": candidate or None,
            "ecosystem": "deb",
            "finding_key": fx.finding_key("apt", None, name, None, None),
            "raw": {
                "inst_line": line,
                "origins": origins,
                "arch": arch,
                "severity_known": False,
                "cve_known": False,
                "note": "apt nu poartă metadate CVE; vezi sentinel/scan/os_packages.py",
            },
        }
    log.info("apt scan parsed",
             extra={"findings": len(seen), "db_version": db_version})
    return list(seen.values()), None, facts
