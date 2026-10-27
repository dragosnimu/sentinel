"""Date comune pentru testele actualizărilor de sistem — fără `test_` în nume, ca pytest să
nu le colecteze.

Forma datelor e cea măsurată pe gazda de producție pe 26 octombrie 2026 (`rpm -q --qf` pe cele 33
de pachete cu constatări deschise, `rpm -q --whatprovides installonlypkg(...)`): trei instanțe de
nucleu instalate în paralel, un `zabbix-web` instalat dintr-o altă serie decât restul familiei (alt
epoch), `kernel-headers` și `kernel-tools` care NU sunt install-only, `openssh-server` în familia
`openssh`. **Versiunile și identificatorii sunt inventate**: depozitul e public, iar nivelul de
patch al unei gazde vii, împreună cu lista constatărilor ei deschise, e o listă a ce se poate
exploata acolo.

Ce NU poate dovedi nimic de aici: că `rpm` de pe o gazdă tipărește exact atât. Formele de ieșire
(codul de ieșire = numărul argumentelor eșuate, «package X is not installed» pe stdout) sunt
copiate din rulări reale; dublura doar le reproduce.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

from sentinel.patch import system_update as su


def rpm_line(name: str, evr: str, arch: str = "x86_64", srpm: str | None = None) -> str:
    """O linie din `rpm -q --qf '%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n'`."""
    if "-" not in evr:
        raise ValueError(evr)
    version_release = evr.split(":", 1)[-1]
    epoch = evr.split(":", 1)[0] if ":" in evr else "(none)"
    return f"{name}\t{epoch}:{version_release}\t{arch}\t{srpm or f'{name}-{version_release}.src.rpm'}"


def _kernel(evr: str) -> list[str]:
    srpm = f"kernel-{evr}.src.rpm"
    return [rpm_line(n, evr, srpm=srpm) for n in ("kernel", "kernel-core", "kernel-modules")]


#: (nume, evr instalat, evr care repară, sursă SRPM sau None = numele). Nucleul e tratat separat.
PACKAGES: list[tuple[str, str, str, str | None]] = [
    ("httpd", "2.4.50-1.el9", "2.4.50-2.el9", "httpd"),
    ("httpd-core", "2.4.50-1.el9", "2.4.50-2.el9", "httpd"),
    ("httpd-tools", "2.4.50-1.el9", "2.4.50-2.el9", "httpd"),
    ("httpd-filesystem", "2.4.50-1.el9", "2.4.50-2.el9", "httpd"),
    ("mod_lua", "2.4.50-1.el9", "2.4.50-2.el9", "httpd"),
    ("openssh", "9.0p1-1.el9", "9.0p1-2.el9", "openssh"),
    ("openssh-server", "9.0p1-1.el9", "9.0p1-2.el9", "openssh"),
    ("openssh-clients", "9.0p1-1.el9", "9.0p1-2.el9", "openssh"),
    ("zabbix-server", "1:6.0.10-1.el9", "1:6.0.12-1.el9", "zabbix"),
    ("zabbix-web", "6.4.1-release1.el9", "1:6.0.12-1.el9", "zabbix"),
    ("expat", "2.5.0-1.el9", "2.5.0-2.el9", "expat"),
    ("libgs", "9.54.0-1.el9", "9.54.0-2.el9", "ghostscript"),
    ("ca-certificates", "2025.2.80-91.el9", "2026.2.92-90.el9", "ca-certificates"),
    ("perl-URI", "5.09-3.el9", "5.09-4.el9", "perl-URI"),
    ("bubblewrap", "0.6.3-1.el9", "0.6.3-2.el9", "bubblewrap"),
    ("librsvg2", "2.50.7-3.el9", "2.50.7-4.el9", "librsvg2"),
    ("libaom", "3.13.3-1.el9", "3.15.2-1.el9", "aom"),
    ("environment-modules", "5.3.0-2.el9", "5.3.0-3.el9", "environment-modules"),
    ("emacs-filesystem", "1:27.2-1.el9", "1:27.2-2.el9", "emacs"),
]

#: Trei nuclee în paralel (install-only), plus două pachete din aceeași sursă care NU sunt.
KERNEL_FIXED = "5.14.0-100.9.el9"
_KERNEL_INSTALLED = ["5.14.0-100.1.el9", "5.14.0-100.2.el9", "5.14.0-100.3.el9"]


def rpm_query_output(extra: list[str] | None = None, *, kernel: bool = True) -> str:
    lines: list[str] = []
    if kernel:
        for evr in _KERNEL_INSTALLED:
            lines += _kernel(evr)
        srpm = f"kernel-{_KERNEL_INSTALLED[-1]}.src.rpm"
        lines += [rpm_line("kernel-headers", _KERNEL_INSTALLED[-1], srpm=srpm),
                  rpm_line("kernel-tools", _KERNEL_INSTALLED[-1], srpm=srpm)]
    for name, installed, _fixed, source in PACKAGES:
        version_release = installed.split(":", 1)[-1]
        lines.append(rpm_line(name, installed, srpm=f"{source or name}-{version_release}.src.rpm"))
    lines += extra or []
    return "\n".join(lines) + "\n"


#: `rpm -q --whatprovides installonlypkg(kernel) ... rpm`: pachetele install-only, plus controlul
#: pozitiv (`rpm`). Două capabilități n-au furnizor, deci codul de ieșire real e 2.
WHATPROVIDES_OUTPUT = (
    "kernel-core\nkernel\nkernel-modules\nkernel-core\nkernel\nkernel-modules\n"
    "kernel-core\nkernel\nkernel-modules\n"
    "no package provides installonlypkg(vm)\nno package provides multiversion(kernel)\nrpm\n")
WHATPROVIDES_FAILURES = 2


def finding_rows(*, kernel: bool = True, extra: list[dict[str, Any]] | None = None,
                 per_package: int = 2) -> list[dict[str, Any]]:
    """Ce întoarce `load_candidates`: câteva constatări pe pachet, cu CVE inventate."""
    rows: list[dict[str, Any]] = []
    n = 1000
    todo = [(name, fixed) for name, _i, fixed, _s in PACKAGES]
    if kernel:
        todo = [(k, KERNEL_FIXED) for k in ("kernel", "kernel-core", "kernel-modules",
                                            "kernel-headers", "kernel-tools")] + todo
    for name, fixed in todo:
        for j in range(per_package):
            n += 1
            rows.append(dict(
                id=n, package=name, cve=f"CVE-2000-{n:04d}", severity="high", kev=False,
                priority=50 + j, fixed_version=fixed, ecosystem="rpm", asset_id=None,
                asset_name=None, asset_protected=False, fix_pending_reboot=False))
    return rows + (extra or [])


class FakeDB:
    """Cât din `Database` ating `system_update`. Notează fiecare interogare ca testele să
    poată citi ce s-a cerut, nu doar ce a întors."""

    def __init__(self, findings: list[dict[str, Any]] | None = None, *,
                 covering: list[dict[str, Any]] | None = None,
                 open_plans: list[dict[str, Any]] | None = None,
                 last_finished: list[dict[str, Any]] | None = None,
                 execution: dict[str, Any] | None = None,
                 detections: list[dict[str, Any]] | None = None,
                 scanners: list[dict[str, Any]] | None = None) -> None:
        self.findings = findings if findings is not None else finding_rows()
        self.covering = covering or []
        self.open_plans = open_plans or []
        self.last_finished = last_finished or []
        self.execution = execution
        self.detections = detections or []
        self.scanners = scanners or []
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        self.calls.append((sql, args))
        if "FROM findings f LEFT JOIN assets" in sql:
            return self.findings
        if "finding_ids &&" in sql:
            return self.covering
        if "generated_by = $1" in sql and "LIMIT 1" in sql:
            return self.last_finished
        if "generated_by = $1" in sql:
            return self.open_plans
        if "FROM detections" in sql:
            return self.detections
        if "GROUP BY scanner" in sql:
            return self.scanners
        raise AssertionError(f"interogare neașteptată: {sql[:80]}")

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        self.calls.append((sql, args))
        if "FROM patch_executions" in sql:
            return self.execution
        raise AssertionError(f"interogare neașteptată: {sql[:80]}")


def cfg(family: str = "rhel") -> Any:
    return SimpleNamespace(platform=SimpleNamespace(family=family))


class FakeHost:
    """Răspunsurile lui `rpm`/`dpkg-query`, ca `system_update._run`. Păstrează argv-urile."""

    def __init__(self, rpm_out: str | None = None, *, provides: str = WHATPROVIDES_OUTPUT,
                 provides_code: int = WHATPROVIDES_FAILURES, rpm_code: int | None = None,
                 dpkg_out: str = "", dpkg_err: str = "", dpkg_code: int = 0) -> None:
        self.rpm_out = rpm_query_output() if rpm_out is None else rpm_out
        self.provides = provides
        self.provides_code = provides_code
        self.rpm_code = rpm_code
        self.dpkg_out, self.dpkg_err, self.dpkg_code = dpkg_out, dpkg_err, dpkg_code
        self.argvs: list[list[str]] = []

    async def __call__(self, argv: list[str], limit_s: int = 20) -> tuple[int, str, str]:
        self.argvs.append(list(argv))
        if argv[0] == "dpkg-query":
            return self.dpkg_code, self.dpkg_out, self.dpkg_err
        if "--whatprovides" in argv:
            return self.provides_code, self.provides, ""
        missing = sum(1 for ln in self.rpm_out.splitlines() if ln.startswith("package "))
        return (self.rpm_code if self.rpm_code is not None else missing), self.rpm_out, ""


def install(monkeypatch: Any, host: FakeHost) -> FakeHost:
    monkeypatch.setattr(su, "_run", host)
    monkeypatch.setattr(su, "_dnf_conf_override", lambda: None)
    return host


def allow_own_programs(monkeypatch: Any) -> None:
    """Lista albă a lui `_run` nu cunoaște interpretorul testului, și bine că nu-l cunoaște. Testele
    care verifică MAȘINĂRIA de pornire (cod de ieșire, 127, timeout) rulează totuși `sys.executable`
    sau un nume inexistent: le lărgește lista, pe durata testului, în mod VIZIBIL — nu printr-o
    ușă lăsată deschisă în cod."""
    monkeypatch.setattr(su, "READ_ONLY_MODE", {sys.executable: "-c", "definitely-not-a-program-xyz": "-q"})
    monkeypatch.setattr(su, "READ_ONLY_FLAGS", {sys.executable: ("-c",),
                                                "definitely-not-a-program-xyz": ("-q",)})
