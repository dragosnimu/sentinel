"""P7 scan core: prioritisation math, package-scanner output parsing, finding keys.

Pure except for the subprocess, which is stubbed: the real `dnf` and `apt-get`
runs happen on the server. What is exercised here is everything that decides
WHICH scanner runs and what is done with an answer — including the answer
"I could not look", which is the one that used to be lost.
"""
from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace

from sentinel.db.repo.findings import finding_key
from sentinel.scan import orchestrator, os_packages, prioritize


# --- prioritisation --------------------------------------------------------
def test_kev_dominates_priority():
    low_cvss_kev = {"severity": "medium", "cvss": 6.5, "kev": True}
    high_cvss_no_kev = {"severity": "critical", "cvss": 9.8}
    # A CVSS 6.5 being actively exploited should rival a 9.8 nobody exploits.
    assert prioritize.score(low_cvss_kev, exposed=True) >= 78


def test_epss_pushes_priority_up():
    base = {"severity": "high", "cvss": 7.0}
    with_epss = {**base, "epss": 0.9}
    assert prioritize.score(with_epss) > prioritize.score(base)


def test_exposure_and_criticality_matter():
    f = {"severity": "high", "cvss": 7.0}
    assert prioritize.score(f, exposed=True, criticality=5) > prioritize.score(f, exposed=False, criticality=1)


def test_priority_is_clamped():
    f = {"severity": "critical", "cvss": 10.0, "kev": True, "epss": 1.0, "fixed_version": "x"}
    assert prioritize.score(f, exposed=True, criticality=5) == 100
    assert prioritize.score({"severity": "info"}, criticality=1) >= 0


# --- dnf output parsing ----------------------------------------------------
_SAMPLE = """\
CVE-2026-1234 Important/Sec.  openssl-libs-1:3.0.7-24.el9_5.x86_64
CVE-2026-9999 Critical/Sec.   kernel-5.14.0-427.el9.x86_64
CVE-2026-1234 Important/Sec.  openssl-1:3.0.7-24.el9_5.x86_64
not a matching line at all
CVE-2026-0001 Low/Sec.        curl-7.76.1-29.el9.x86_64
"""


def test_split_nvra():
    assert os_packages._split_nvra("openssl-libs-1:3.0.7-24.el9_5.x86_64")[0] == "openssl-libs"
    assert os_packages._split_nvra("kernel-5.14.0-427.el9.x86_64")[0] == "kernel"


def test_line_regex_maps_severity():
    m = os_packages._LINE.match("CVE-2026-9999 Critical/Sec.   kernel-5.14.0-427.el9.x86_64")
    assert m and m.group("cve") == "CVE-2026-9999"
    assert os_packages._SEV["critical"] == "critical"
    assert os_packages._SEV["important"] == "high"
    assert os_packages._SEV["moderate"] == "medium"


# --- finding key -----------------------------------------------------------
def test_finding_key_is_stable_and_distinct():
    k1 = finding_key("dnf", None, "openssl", "CVE-2026-1234", None)
    k2 = finding_key("dnf", None, "openssl", "CVE-2026-1234", None)
    k3 = finding_key("dnf", None, "kernel", "CVE-2026-1234", None)
    assert k1 == k2 and k1 != k3 and len(k1) == 64


# ===========================================================================
# Platform family -> scanner selection
# ===========================================================================
# The bug this whole block exists for: on Ubuntu the runtime ran `dnf`, the
# command did not exist, the failure was logged and the pass continued — so the
# dashboard showed zero OS vulnerabilities on a host nobody had ever scanned.
# Absence of a finding was read as health.
def _run(coro):
    return asyncio.run(coro)


# An `apt-get -s dist-upgrade` extract in the shape apt's own simulation code
# produces. Two security upgrades (one of them also in -updates, which is how
# Ubuntu publishes), one plain -updates upgrade that must NOT be reported, one
# newly-installed kernel package with no installed-version bracket, and the Conf
# lines apt emits alongside.
_APT_SAMPLE = """\
NOTE: This is only a simulation!
Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  libssl3t64 openssl tzdata
Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Conf libssl3t64 (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst tzdata [2024a-3ubuntu1] (2024b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])
Inst linux-image-6.8.0-45-generic (6.8.0-45.45 Ubuntu:24.04/noble-security [amd64])
Conf tzdata (2024b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])
"""


def _apt_host(monkeypatch, *, out=_APT_SAMPLE, rc=0, err="",
              indexes=(40, 6), newest=None):
    """Make the debian backend believe it is on a normal Ubuntu host.

    Every gate it checks before running apt is stubbed here, so that a test
    about parsing is not silently answered by an early return about missing
    indexes. Returns the list of calls the backend actually made.

    The stub's signature has NO default for `timeout` either: a stub that
    accepted a missing timeout would let the production code stop passing one
    and this whole file would stay green.
    """
    from datetime import datetime, timezone

    calls: list[dict] = []

    async def fake_run(argv, timeout, env=None):
        calls.append({"argv": argv, "timeout": timeout, "env": env})
        return rc, out, err

    monkeypatch.setattr(os_packages.shutil, "which", lambda _n: "/usr/bin/apt-get")
    monkeypatch.setattr(
        os_packages, "_apt_index_state",
        lambda: (indexes[0], indexes[1], newest or datetime.now(timezone.utc), None))
    monkeypatch.setattr(os_packages, "_run", fake_run)
    return calls


def test_the_family_decides_which_command_runs(monkeypatch):
    """The trap: a `debian` branch that exists but never runs anything.

    An installer that writes platform.family=debian while the runtime keeps
    shelling out to dnf leaves the Ubuntu host exactly as unscanned as before,
    with a config key that claims otherwise. So assert on the argv that reached
    the subprocess, not on the presence of a branch.
    """
    calls = _apt_host(monkeypatch)

    _run(os_packages.scan("rhel"))
    assert calls[-1]["argv"][0] == "dnf", "rhel must still run dnf"

    _run(os_packages.scan("debian"))
    assert calls[-1]["argv"][0] == "apt-get", "debian must run apt-get, not dnf"
    assert "dist-upgrade" in calls[-1]["argv"] and "-s" in calls[-1]["argv"], \
        "the apt call must be a simulation; a real dist-upgrade would install"


def test_run_takes_a_mandatory_timeout_and_every_backend_passes_one(monkeypatch):
    """Un implicit ar face ca plafonul unui backend să fie moștenit de celălalt.

    Același defect pe care `trivy_fs._run` l-a scos: un buget scris ca implicit
    devine bugetul fiecărui apel care uită să spună altceva. Aici sunt două
    comenzi cu două plafoane, iar dacă una ar rula fără să-l ceară pe al ei,
    scanarea ar putea depăși `TimeoutStartSec` și ar lăsa un rând `running`
    peste ultimul rezultat real din panou.
    """
    assert (inspect.signature(os_packages._run).parameters["timeout"].default
            is inspect.Parameter.empty)

    calls = _apt_host(monkeypatch)
    _run(os_packages.scan("rhel"))
    assert calls[-1]["timeout"] == os_packages.TIMEOUT_S
    _run(os_packages.scan("debian"))
    assert calls[-1]["timeout"] == os_packages.APT_TIMEOUT_S


def test_the_module_worst_case_is_derived_from_both_budgets():
    """Bugetul unității se împarte între scanere, iar pe o gazdă rulează o
    singură familie — deci ce trebuie să încapă în `TimeoutStartSec` e MAXIMUL
    celor două plafoane.

    Verificat și pe sursă, nu doar ca inegalitate: azi `TIMEOUT_S` e cel mare,
    deci un `WORST_CASE_TIMEOUT_S = TIMEOUT_S` scris de mână ar satisface orice
    comparație numerică — și ar rămâne așa până în ziua în care cineva ridică
    plafonul lui apt, când unitatea ar fi omorâtă la mijloc și scanerul din coadă
    n-ar mai rula deloc.
    """
    from pathlib import Path

    assert os_packages.WORST_CASE_TIMEOUT_S >= os_packages.TIMEOUT_S
    assert os_packages.WORST_CASE_TIMEOUT_S >= os_packages.APT_TIMEOUT_S

    source = (Path(os_packages.__file__)).read_text(encoding="utf-8")
    assert "WORST_CASE_TIMEOUT_S = max(TIMEOUT_S, APT_TIMEOUT_S)" in source, (
        "`WORST_CASE_TIMEOUT_S` nu mai e derivat din amândouă plafoanele")


def test_scanner_name_follows_the_family():
    """`scans.scanner` and every per-scanner self-check key hang off this name.
    If both families reported under 'dnf', an Ubuntu host's failures would be
    filed under a scanner that never ran there."""
    assert os_packages.scanner_for("rhel") == "dnf"
    assert os_packages.scanner_for("debian") == "apt"
    assert os_packages.scanner_for("suse") == os_packages.UNKNOWN_SCANNER


def test_unknown_family_is_an_error_not_an_empty_scan():
    """A family Sentinel cannot scan must say so. Returning an empty finding
    list would be indistinguishable from a host with nothing wrong."""
    findings, error, facts = _run(os_packages.scan("suse"))
    assert findings == []
    assert error and "suse" in error
    assert facts["scanner"] == os_packages.UNKNOWN_SCANNER


# --- what the apt backend reports, and what it refuses to invent ------------
def test_apt_reports_only_the_security_pocket(monkeypatch):
    """Reporting every pending update as a security finding would bury the ones
    that are, and teach the operator to ignore the list."""
    _apt_host(monkeypatch)
    findings, error, _ = _run(os_packages.scan("debian"))

    assert error is None
    packages = {f["package"] for f in findings}
    assert packages == {"libssl3t64", "linux-image-6.8.0-45-generic"}
    assert "tzdata" not in packages, \
        "tzdata is a plain -updates upgrade and is not a security finding"


def test_apt_findings_invent_neither_cve_nor_severity(monkeypatch):
    """apt carries no CVE and no severity. A finding that showed either would be
    a number the operator cannot check and cannot look up — and would make the
    debian path look as authoritative as the RHEL one, which it is not."""
    _apt_host(monkeypatch)
    findings, _, _ = _run(os_packages.scan("debian"))

    ssl = next(f for f in findings if f["package"] == "libssl3t64")
    assert ssl["cve"] is None
    assert ssl["raw"]["cve_known"] is False
    assert ssl["raw"]["severity_known"] is False
    # The limitation travels with the finding into the dashboard and Telegram,
    # not only into a docstring nobody reads at 3 a.m.
    assert "NU o evaluare" in ssl["description"]
    assert ssl["installed_version"] == "3.0.13-0ubuntu3.4"
    assert ssl["fixed_version"] == "3.0.13-0ubuntu3.5"
    assert ssl["ecosystem"] == "deb"


def test_apt_grades_an_ungraded_finding_the_same_way_trivy_does(monkeypatch):
    """Două scanere care spun „nu știu" trebuie s-o spună la fel.

    `trivy_fs.map_severity` întoarce (`medium`, `False`) pentru `UNKNOWN`, și nu
    `info`, fiindcă `info` e o afirmație — „ne-am uitat, e neglijabil" — iar
    absența unei note nu e. Dacă backend-ul apt ar alege altă valoare, aceeași
    stare ar apărea în panou sub două severități și orice filtru de triaj ar
    ascunde una dintre ele.
    """
    from sentinel.scan.trivy_fs import map_severity

    _apt_host(monkeypatch)
    findings, _, _ = _run(os_packages.scan("debian"))
    ssl = next(f for f in findings if f["package"] == "libssl3t64")

    assert (ssl["severity"], ssl["raw"]["severity_known"]) == map_severity("UNKNOWN")
    assert ssl["severity"] != "info"


def test_apt_finding_key_is_namespaced_to_apt(monkeypatch):
    """Sharing a key namespace with dnf would let one scanner's clean run
    resolve the other scanner's open findings."""
    _apt_host(monkeypatch)
    findings, _, _ = _run(os_packages.scan("debian"))
    ssl = next(f for f in findings if f["package"] == "libssl3t64")
    assert ssl["scanner"] == "apt"
    assert ssl["finding_key"] == finding_key("apt", None, "libssl3t64", None, None)
    assert ssl["finding_key"] != finding_key("dnf", None, "libssl3t64", None, None)


def test_apt_reports_a_package_with_no_installed_version(monkeypatch):
    """A newly installed kernel has no `[old-version]` bracket. An expression
    that required one would silently drop every kernel security update — the
    single most important row on the page."""
    _apt_host(monkeypatch)
    findings, _, _ = _run(os_packages.scan("debian"))
    kern = next(f for f in findings
                if f["package"] == "linux-image-6.8.0-45-generic")
    assert kern["installed_version"] is None
    assert kern["fixed_version"] == "6.8.0-45.45"


def test_split_apt_body():
    assert os_packages._split_apt_body(
        "3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64]"
    ) == ("3.0.13-0ubuntu3.5",
          "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security", "amd64")


def test_a_host_with_nothing_pending_is_a_real_clean_result(monkeypatch):
    """Cealaltă direcție a refuzurilor de mai jos, și cea care se uită ușor.

    Un backend care refuză prea larg nu mai raportează niciodată curat, iar
    `scan:last:apt` rămâne roșu la nesfârșit — un roșu permanent e la fel de
    necitit ca un verde permanent. O gazdă cu indexuri, cu index de securitate
    și fără nicio linie `Inst` chiar E curată.
    """
    _apt_host(monkeypatch, out="NOTE: This is only a simulation!\n"
                               "Reading package lists...\n"
                               "0 upgraded, 0 newly installed, 0 to remove.\n")
    findings, error, facts = _run(os_packages.scan("debian"))
    assert findings == [] and error is None
    assert facts["db_version"] and facts["db_version"].startswith("apt-lists ")


# --- the states where apt must refuse to say "clean" ------------------------
def test_apt_refuses_to_report_clean_without_package_indexes(monkeypatch):
    """`apt-get -s dist-upgrade` on a host where `apt-get update` never ran
    prints 0 upgrades and exits 0. Believing it would put a green panel on a
    machine whose package data does not exist."""
    _apt_host(monkeypatch, out="", indexes=(0, 0))
    findings, error, _ = _run(os_packages.scan("debian"))
    assert findings == []
    # The specific message, not just "some error": the two index gates below
    # produce different diagnoses and must not stand in for each other.
    assert error and "nu a rulat niciodată aici" in error


def test_apt_refuses_to_report_clean_without_a_security_index(monkeypatch):
    """A sources.list with no -security pocket means the host receives no
    security updates at all. Zero findings there is the most dangerous zero on
    the dashboard, and it must be reported as a failure to look."""
    _apt_host(monkeypatch, out=_APT_SAMPLE, indexes=(40, 0))
    findings, error, _ = _run(os_packages.scan("debian"))
    assert findings == []
    assert error and "nu primește actualizări de securitate" in error


def test_apt_missing_binary_is_an_error(monkeypatch):
    """platform.family=debian on a host with no apt-get is a broken assumption,
    not a clean scan."""
    # Healthy indexes first, so the only thing this test can be answered by is
    # the missing binary — not by an index gate firing for its own reasons.
    _apt_host(monkeypatch)
    monkeypatch.setattr(os_packages.shutil, "which", lambda _n: None)
    findings, error, _ = _run(os_packages.scan("debian"))
    assert findings == [] and error and "apt-get nu există" in error


def test_apt_nonzero_exit_is_an_error_even_with_output(monkeypatch):
    """apt-get uses 100 for errors, where dnf uses it for 'updates available'.
    Copying the dnf rule across would turn a broken package database into a
    clean report."""
    _apt_host(monkeypatch,
              out="Inst x [1] (2 Ubuntu:24.04/noble-security [amd64])",
              rc=100, err="E: Unable to correct problems")
    findings, error, _ = _run(os_packages.scan("debian"))
    assert findings == []
    assert error and "Unable to correct problems" in error


def test_apt_refuses_an_inst_line_it_cannot_parse(monkeypatch):
    """Formatul liniei `Inst` e fixat din sursa lui apt, nu de pe o gazdă reală.

    Deci a fi greșit despre el e o posibilitate, iar o linie sărită în tăcere nu
    e doar una neraportată: `mark_resolved_absent` rulează pe lista întoarsă,
    deci constatarea pe care linia aia o producea se ÎNCHIDE. O actualizare de
    securitate ar dispărea din panou tocmai fiindcă n-am înțeles-o.
    """
    _apt_host(monkeypatch, out=(
        "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 "
        "Ubuntu:24.04/noble-security [amd64])\n"
        "Inst ceva-ce-nu-seamana-cu-nimic\n"))
    findings, error, _ = _run(os_packages.scan("debian"))
    assert findings == []
    assert error and "nu au forma așteptată" in error
    assert "ceva-ce-nu-seamana-cu-nimic" in error, \
        "eroarea trebuie să arate linia, altfel nimeni nu poate repara expresia"


def test_apt_refuses_output_whose_inst_lines_carry_no_origin(monkeypatch):
    """Câmpul de origine e SINGURUL lucru care deosebește o actualizare de
    securitate de una obișnuită.

    Dacă apt încetează să-l scrie — sau dacă am greșit unde e —, filtrul de mai
    jos n-ar păstra nimic și scanarea ar raporta o gazdă curată. Exact forma
    bug-ului pentru care modulul ăsta a fost rescris, întoarsă pe altă ușă.
    """
    _apt_host(monkeypatch, out=(
        "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5)\n"
        "Inst tzdata [2024a-3ubuntu1] (2024b-0ubuntu0.24.04)\n"))
    findings, error, _ = _run(os_packages.scan("debian"))
    assert findings == []
    assert error and "câmpul de origine" in error


def test_apt_tolerates_one_package_without_an_origin(monkeypatch):
    """Refuzul de mai sus n-are voie să fie prea larg.

    apt scrie o origine goală pentru o versiune fără sursă — un `.deb` instalat
    local. Un pachet ca ăsta chiar nu e în depozitul de securitate, iar dacă
    prezența lui ar opri toată scanarea, `scan:last:apt` ar fi roșu permanent pe
    o gazdă perfect normală, și nimeni n-ar mai citi cheia.
    """
    _apt_host(monkeypatch, out=(
        "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 "
        "Ubuntu:24.04/noble-security [amd64])\n"
        "Inst ceva-local [1.0] (2.0  [amd64])\n"))
    findings, error, _ = _run(os_packages.scan("debian"))
    assert error is None
    assert {f["package"] for f in findings} == {"libssl3t64"}


def test_apt_records_how_old_its_metadata_is(monkeypatch):
    """A clean report from a three-week-old index is a partial picture. The age
    goes onto the `scans` row so the operator is not shown a fresh-looking clean
    result — `scans.db_version` is the field the schema reserves for it."""
    from datetime import datetime, timedelta, timezone

    old = datetime.now(timezone.utc) - timedelta(days=21)
    _apt_host(monkeypatch, newest=old)
    _, _, facts = _run(os_packages.scan("debian"))
    assert facts["db_version"] and old.date().isoformat() in facts["db_version"]
    assert "21 zile" in facts["db_version"]


def test_a_failed_apt_run_still_says_what_it_looked_with(monkeypatch):
    """„Ce a văzut scanarea" fără „cu ce metadate s-a uitat" e o cifră căreia nu
    i se mai poate afla valabilitatea nici a doua zi. `trivy_fs` duce deja
    `db_version` pe drumurile de eroare, din același motiv."""
    _apt_host(monkeypatch, out="", rc=100, err="E: ceva")
    _, error, facts = _run(os_packages.scan("debian"))
    assert error
    assert facts["db_version"] and facts["db_version"].startswith("apt-lists ")


# --- the RHEL path must be untouched ---------------------------------------
def test_rhel_scan_is_unchanged(monkeypatch):
    """AlmaLinux is in production. The dnf command, the parsing and the finding
    keys must be exactly what they were before the family split — including the
    private cache directory, without which the scan took 82 seconds and died."""
    calls: list[dict] = []

    async def fake_run(argv, timeout, env=None):
        calls.append({"argv": argv, "timeout": timeout})
        return 100, _SAMPLE, ""

    monkeypatch.setattr(os_packages, "_run", fake_run)
    findings, error, facts = _run(os_packages.scan("rhel"))

    assert [c["argv"] for c in calls] == [[
        "dnf", "-q", f"--setopt=cachedir={os_packages.CACHE_DIR}",
        "updateinfo", "list", "cves", "--security"]]
    assert facts["scanner"] == "dnf" and error is None
    # Four (CVE, package) pairs in the sample; the non-matching line is dropped.
    assert len(findings) == 4
    kernel = next(f for f in findings if f["package"] == "kernel")
    assert kernel["cve"] == "CVE-2026-9999"
    assert kernel["severity"] == "critical"
    assert kernel["ecosystem"] == "rpm"
    assert kernel["scanner"] == "dnf"
    assert kernel["finding_key"] == finding_key(
        "dnf", None, "kernel", "CVE-2026-9999", None)


def test_rhel_hard_failure_is_still_an_error(monkeypatch):
    """A dnf that cannot reach its metadata must fail the scan, not return an
    empty list that resolves every open finding on the production host."""
    async def fake_run(argv, timeout, env=None):
        return 1, "", "Failed to download metadata"

    monkeypatch.setattr(os_packages, "_run", fake_run)
    findings, error, _ = _run(os_packages.scan("rhel"))
    assert findings == [] and "Failed to download metadata" in error


# ===========================================================================
# Orchestrator: a scanner that could not look must leave a visible record
# ===========================================================================
class _FakeDB:
    """Records what the orchestrator asked the database to do."""

    def __init__(self):
        self.scan_ids = 0
        self.executed: list[tuple[str, tuple]] = []
        self.fetched: list[tuple[str, tuple]] = []
        self.upserted: list[tuple] = []

    async def fetchval(self, sql, *args):
        self.scan_ids += 1
        self.executed.append((sql, args))
        return self.scan_ids

    async def execute(self, sql, *args):
        self.executed.append((sql, args))

    async def fetch(self, sql, *args):
        self.fetched.append((sql, args))
        return []

    async def fetchrow(self, sql, *args):
        self.upserted.append(args)
        return {"is_new": True, "status": "open"}


def _sql_of(calls, needle):
    return [(sql, args) for sql, args in calls if needle in sql]


def test_failed_scan_records_a_failed_row_and_resolves_nothing(monkeypatch):
    """The failure this prevents: a scanner that cannot run reports zero
    findings, every open vulnerability is marked 'absent from the latest scan',
    and the operator is shown a host that repaired itself overnight."""
    db = _FakeDB()

    async def dead(family):
        return [], "apt-get lipseste", {"scanner": "apt", "family": family,
                                        "db_version": None}

    monkeypatch.setattr(orchestrator.os_packages, "scan", dead)
    out = _run(orchestrator._run_os_packages(db, "debian", "schedule"))

    assert out["status"] == "failed"
    assert not _sql_of(db.fetched, "absent_from_latest_scan"), \
        "a failed scan must never resolve findings it did not look at"
    finished = _sql_of(db.executed, "UPDATE scans SET status")
    assert finished and finished[0][1][1] == "failed"
    assert "apt-get lipseste" in finished[0][1][6]


def test_scan_row_is_opened_under_the_scanner_the_family_selects(monkeypatch):
    """`scans.scanner` is how the self-check knows whether the OS scanner ran at
    all. Filing an Ubuntu host's runs under 'dnf' would make "dnf has not run
    for 40 days" impossible to tell from a healthy Ubuntu host — and renaming
    the RHEL one would throw away `scan:last:dnf`'s history on production."""
    async def stub(family):
        return [], "stub", {"scanner": os_packages.scanner_for(family),
                            "family": family, "db_version": None}

    monkeypatch.setattr(orchestrator.os_packages, "scan", stub)

    for family, expected in (("rhel", "dnf"), ("debian", "apt"),
                             ("suse", "os_packages")):
        db = _FakeDB()
        _run(orchestrator._run_os_packages(db, family, "schedule"))

        opened = _sql_of(db.executed, "INSERT INTO scans")
        assert opened, f"{family}: no scans row was opened"
        assert opened[0][1][0] == expected, \
            f"{family}: scans row filed under {opened[0][1][0]!r}, expected {expected!r}"


def test_a_failed_scan_resolves_under_no_other_scanner_name(monkeypatch):
    """Reversul: după o rulare ÎNCHEIATĂ, curățenia trebuie făcută sub numele
    scanerului care a rulat. Sub un nume fix, o rulare apt curată ar închide
    constatările lui dnf și invers — un scaner ar șterge munca celuilalt."""
    db = _FakeDB()

    async def clean(family):
        return [], None, {"scanner": os_packages.scanner_for(family),
                          "family": family, "db_version": None}

    monkeypatch.setattr(orchestrator.os_packages, "scan", clean)
    _run(orchestrator._run_os_packages(db, "debian", "schedule"))

    resolved = _sql_of(db.fetched, "absent_from_latest_scan")
    assert resolved, "o rulare încheiată trebuie să facă și curățenia"
    assert resolved[0][1][0] == "apt", \
        f"curățenia s-a făcut sub {resolved[0][1][0]!r}, nu sub scanerul care a rulat"


def test_a_scanner_without_a_severity_floor_still_closes_everything(monkeypatch):
    """Garda de severitate a lui `trivy_image` nu are voie să îngrădească dnf/apt.

    Eșecul pe care îl previne: `mark_resolved_absent` a primit pe 29 august 2026
    o îngrădire opțională, ca o rulare la un prag ridicat să nu închidă
    constatările de sub el. Aplicată din greșeală și scanerelor care NU filtrează
    la sursă, constatările reparate de operator ar rămâne deschise pentru
    totdeauna — panoul ar arăta vulnerabilități care nu mai există, adică exact
    inversul pauzei din 21 august, și la fel de scump.
    """
    db = _FakeDB()

    async def clean(family):
        return [], None, {"scanner": os_packages.scanner_for(family),
                          "family": family, "db_version": None}

    monkeypatch.setattr(orchestrator.os_packages, "scan", clean)
    _run(orchestrator._run_os_packages(db, "debian", "schedule"))

    (sql, args) = _sql_of(db.fetched, "absent_from_latest_scan")[0]
    assert "severity = ANY" not in sql, (
        f"curățenia lui apt e îngrădită de severitate: {sql}")
    assert len(args) == 3, f"parametri în plus pe o rulare fără prag: {args}"


def test_unrecognised_family_still_leaves_a_scans_row():
    """A config with a mistyped family must produce a visible failed scan, not
    silence. Silence is the state that reads as 'no vulnerabilities'."""
    db = _FakeDB()
    out = _run(orchestrator._run_os_packages(db, "ubuntu", "schedule"))

    assert out["status"] == "failed"
    assert _sql_of(db.executed, "INSERT INTO scans")
    finished = _sql_of(db.executed, "UPDATE scans SET status")
    assert finished and finished[0][1][1] == "failed"


def test_completed_scan_carries_the_metadata_age_onto_the_row(monkeypatch):
    """Without db_version, a clean apt scan from a stale index looks exactly
    like a clean apt scan from a fresh one."""
    db = _FakeDB()

    async def ok(family):
        return [], None, {"scanner": "apt", "family": family,
                          "db_version": "apt-lists 2026-08-01T03:00:00+00:00"}

    monkeypatch.setattr(orchestrator.os_packages, "scan", ok)
    _run(orchestrator._run_os_packages(db, "debian", "schedule"))

    finished = _sql_of(db.executed, "UPDATE scans SET status")
    assert finished[0][1][1] == "completed"
    assert finished[0][1][7] == "apt-lists 2026-08-01T03:00:00+00:00"


def test_a_finding_without_a_cve_is_never_marked_kev(monkeypatch):
    """Ce ține calea de patch închisă pe Debian, verificat ca efect.

    `generate_for_kev` alege pe `findings.kev`, iar `kev` se pune doar când CVE-ul
    constatării e în oglinda KEV. O constatare apt n-are CVE, deci nu poate fi
    KEV, deci nu se generează niciun plan din ea. Dacă bucla ar pune totuși
    steagul, Sentinel ar schița un plan de patch pentru o „vulnerabilitate" pe
    care nimeni n-o poate căuta.
    """
    db = _FakeDB()

    async def apt_result(family):
        return [{"scanner": "apt", "cve": None, "package": "libssl3t64",
                 "severity": "medium", "fixed_version": "3.0.13-0ubuntu3.5",
                 "finding_key": finding_key("apt", None, "libssl3t64", None, None),
                 "raw": {}}], None, {"scanner": "apt", "family": family,
                                     "db_version": None}

    monkeypatch.setattr(orchestrator.os_packages, "scan", apt_result)
    out = _run(orchestrator._run_os_packages(db, "debian", "schedule"))

    assert out["status"] == "completed" and out["findings"] == 1
    item = out["new_items"][0]
    assert item.get("kev") is None and "kev_due_date" not in item


def test_new_findings_still_travel_to_the_announcement(monkeypatch):
    """`run_all` adună `new_items` din fiecare scaner ca să trimită anunțul.

    Reconcilierea a schimbat forma răspunsului scanerului de pachete; dacă
    `new_items` ar fi căzut pe drum, scanarea ar continua să scrie în bază și
    operatorul n-ar mai primi niciun mesaj despre CVE-urile noi de sistem —
    tăcere care arată identic cu „n-a fost nimic nou".
    """
    db = _FakeDB()

    async def one(family):
        return [{"scanner": "dnf", "cve": "CVE-2026-1234", "package": "openssl",
                 "severity": "high", "fixed_version": "3.0.7-25",
                 "finding_key": finding_key("dnf", None, "openssl",
                                            "CVE-2026-1234", None),
                 "raw": {}}], None, {"scanner": "dnf", "family": family,
                                     "db_version": None}

    monkeypatch.setattr(orchestrator.os_packages, "scan", one)
    out = _run(orchestrator._run_os_packages(db, "rhel", "schedule"))
    assert [f["cve"] for f in out["new_items"]] == ["CVE-2026-1234"]


def test_run_all_keys_the_summary_by_the_scanner_that_ran(monkeypatch):
    """The journal line at the end of a pass names the scanner. On AlmaLinux it
    must still say 'dnf' — the key is what an operator greps for."""
    db = _FakeDB()

    async def no_refresh(_db):
        return None

    async def ran(_db, _family, _triggered):
        return {"status": "completed"}

    async def no_plans(_db, _cfg):
        return {"status": "disabled"}

    monkeypatch.setattr(orchestrator.kev, "refresh", no_refresh)
    monkeypatch.setattr(orchestrator, "_run_os_packages", ran)
    monkeypatch.setattr(orchestrator, "_draft_plans", no_plans)

    for family, expected in (("rhel", "dnf"), ("debian", "apt")):
        cfg = SimpleNamespace(
            scan=SimpleNamespace(enabled=True, os_packages=True,
                                 filesystem=False, containers=False),
            platform=SimpleNamespace(family=family))
        summary = _run(orchestrator.run_all(db, cfg))
        assert expected in summary, f"{family}: summary keys were {sorted(summary)}"
