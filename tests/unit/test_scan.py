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


# --- the shape a real Ubuntu host actually printed -------------------------
# Măsurat pe 14 septembrie 2026 pe gazda Ubuntu 24.04.4 LTS (noble), apt 2.8.3,
# cu chiar comanda scanerului: `apt-get -s -q -o Debug::NoLocking=true
# dist-upgrade`. Cele 15 linii `Inst` sunt copiate verbatim, nu rescrise: o formă
# măsurată o dată valorează mai mult decât o duzină inventate, iar linia care a
# oprit șapte scanări programate la rând e una dintre ele.
#
# A zecea poartă un al doilea grup de paranteze drepte DUPĂ paranteza rotundă.
# `apt-get(8)` îl descrie la `-s`: „Square brackets indicate broken packages, and
# empty square brackets indicate breaks that are of no consequence (rare)" — o
# listă de pachete rupte pentru o clipă în timpul simulării, fără versiune, fără
# origine și fără arhitectură.
_APT_REAL_NOBLE = """\
Inst motd-news-config [13ubuntu10.4] (13ubuntu10.5 Ubuntu:24.04/noble-updates [all])
Inst base-files [13ubuntu10.4] (13ubuntu10.5 Ubuntu:24.04/noble-updates [amd64])
Inst docker-ce-cli [5:29.7.2-1~ubuntu.24.04~noble] (5:29.8.0-1~ubuntu.24.04~noble Docker CE:noble [amd64])
Inst containerd.io [2.3.3-1~ubuntu.24.04~noble] (2.3.5-1~ubuntu.24.04~noble Docker CE:noble [amd64])
Inst docker-ce [5:29.7.2-1~ubuntu.24.04~noble] (5:29.8.0-1~ubuntu.24.04~noble Docker CE:noble [amd64])
Inst libproc2-0 [2:4.0.4-4ubuntu3.2] (2:4.0.4-4ubuntu3.3 Ubuntu:24.04/noble-updates [amd64])
Inst procps [2:4.0.4-4ubuntu3.2] (2:4.0.4-4ubuntu3.3 Ubuntu:24.04/noble-updates [amd64])
Inst python-apt-common [2.7.7ubuntu5.2] (2.7.7ubuntu5.3 Ubuntu:24.04/noble-updates [all])
Inst python3-apt [2.7.7ubuntu5.2] (2.7.7ubuntu5.3 Ubuntu:24.04/noble-updates [amd64])
Inst ubuntu-release-upgrader-core [1:24.04.28] (1:24.04.29 Ubuntu:24.04/noble-updates [all]) []
Inst python3-distupgrade [1:24.04.28] (1:24.04.29 Ubuntu:24.04/noble-updates [all])
Inst byobu [6.11-0ubuntu1] (6.11-0ubuntu1.1 Ubuntu:24.04/noble-updates [all])
Inst docker-buildx-plugin [0.36.1-1~ubuntu.24.04~noble] (0.37.1-1~ubuntu.24.04~noble Docker CE:noble [amd64])
Inst docker-ce-rootless-extras [5:29.7.2-1~ubuntu.24.04~noble] (5:29.8.0-1~ubuntu.24.04~noble Docker CE:noble [amd64])
Inst docker-compose-plugin [5.5.0-1~ubuntu.24.04~noble] (5.5.1-1~ubuntu.24.04~noble Docker CE:noble [amd64])
"""

#: Linia măsurată care poartă grupul de la sfârșit, ca să nu fie căutată prin
#: fixtură cu un index care se poate muta.
_APT_REAL_WITH_TRAILING_GROUP = (
    "Inst ubuntu-release-upgrader-core [1:24.04.28] "
    "(1:24.04.29 Ubuntu:24.04/noble-updates [all]) []")

#: Măsurată pe aceeași gazdă pe 12 septembrie 2026 și păstrată în `scans.error`
#: al scanării care a eșuat atunci: una dintre cele zece linii pe care parserul
#: nu le-a putut citi. E singura formă REALĂ care are deodată buzunar de
#: securitate, două origini și grupul de paranteze de la sfârșit — adică singura
#: dovadă că drumul de la potrivire la constatare merge cu grupul prezent. O
#: linie inventată cu aceeași formă n-ar dovedi decât că expresia se potrivește
#: cu ce i-am scris noi.
_APT_REAL_SECURITY_WITH_TRAILING_GROUP = (
    "Inst libc6-dev [2.39-0ubuntu8.8] (2.39-0ubuntu8.9 "
    "Ubuntu:24.04/noble-security, Ubuntu:24.04/noble-updates [amd64]) []")


def test_every_measured_inst_line_parses(monkeypatch):
    """Eșecul pe care îl previne: o singură formă de linie nerecunoscută oprește
    toată scanarea, iar operatorul rămâne fără răspuns la „am actualizări de
    securitate în așteptare?".

    S-a întâmplat, și se citește în `scans`: șapte scanări programate la rând au
    eșuat între 9 și 14 septembrie 2026 — cinci zile —, cu „1 din 15 linii `Inst`
    (…) nu au forma așteptată" la majoritatea rulărilor și „10 din 29" pe 12
    septembrie. Programate, nu „de noapte": șase au pornit imediat după miezul
    nopții, dar una a rulat la 11:45 UTC, iar numărarea lor ca nopți e felul în
    care șapte rulări se transformă în alt număr de zile decât au fost. Refuzul
    era corect, o formă neînțeleasă n-are voie să
    fie sărită; prețul lui e că o scanare eșuată nu rulează
    `mark_resolved_absent`, deci pe un scaner care chiar scrisese constatări ele
    ar fi rămas și deschise pe deasupra.
    """
    lines = [ln for ln in _APT_REAL_NOBLE.splitlines() if ln.strip()]
    assert len(lines) == 15, (
        "fixtura măsurată s-a scurtat; un test rămas fără date de rulat trece "
        "fără să verifice nimic")

    parsed, error = os_packages._read_inst_lines(_APT_REAL_NOBLE)
    assert error is None, f"ieșirea reală a gazdei e respinsă: {error}"
    assert len(parsed) == 15

    # Nu doar „a potrivit": fiecare linie trebuie să dea numele, versiunea
    # candidată și originea. O potrivire care lasă câmpurile goale ar trece de o
    # aserțiune pe `error is None` și ar produce constatări fără conținut.
    for line, m in parsed:
        candidate, origins, _arch = os_packages._split_apt_body(m.group("body"))
        assert m.group("name") and candidate and origins, \
            f"câmpuri lipsă după potrivire: {line}"
    assert [m.group("name") for _l, m in parsed][:3] == [
        "motd-news-config", "base-files", "docker-ce-cli"]
    assert _APT_REAL_WITH_TRAILING_GROUP in [ln for ln, _m in parsed], \
        "linia cu grupul de la sfârșit nu mai e în fixtură"


def test_the_trailing_broken_list_is_ignored_not_parsed():
    """Eșecul pe care îl previne: versiunea, originea sau arhitectura citite
    dintr-un grup care nu poartă niciuna dintre ele.

    Grupul de după paranteză e o listă de pachete rupte momentan. Dacă ar fi
    citit ca arhitectură, `raw.arch` ar deveni un nume de pachet; dacă ar intra
    în corp, originea — singurul lucru care deosebește o actualizare de
    securitate de una obișnuită — ar fi dusă de un grup care n-o conține.
    """
    m = os_packages._APT_INST.match(_APT_REAL_WITH_TRAILING_GROUP)
    assert m, "linia reală cu grup la sfârșit nu potrivește"
    assert m.group("name") == "ubuntu-release-upgrader-core"
    assert m.group("installed") == "1:24.04.28"
    assert os_packages._split_apt_body(m.group("body")) == (
        "1:24.04.29", "Ubuntu:24.04/noble-updates", "all")

    # Aceeași linie fără grup: fiecare câmp trebuie să iasă identic. Altfel
    # toleranța ar fi cumpărat parsarea unei linii cu prețul alteia.
    fara = _APT_REAL_WITH_TRAILING_GROUP[:-len(" []")]
    m2 = os_packages._APT_INST.match(fara)
    assert m2 and m2.groups() == m.groups()

    # Varianta NEGOALĂ, pe care apt o documentează ca rară și pe care n-am
    # văzut-o: numele dinăuntru n-au voie să ajungă în niciun câmp.
    m3 = os_packages._APT_INST.match(
        "Inst foo [1] (2 Ubuntu:24.04/noble-updates [all]) [bar baz ]")
    assert m3 and m3.group("name") == "foo"
    assert os_packages._split_apt_body(m3.group("body")) == (
        "2", "Ubuntu:24.04/noble-updates", "all")

    # Și o linie fără arhitectură deloc, dar cu lista de rupte: arhitectura
    # rămâne goală, nu devine „bar".
    m4 = os_packages._APT_INST.match("Inst foo [1] (2 Ubuntu:24.04/noble-security) [bar]")
    assert m4 and os_packages._split_apt_body(m4.group("body")) == (
        "2", "Ubuntu:24.04/noble-security", "")


def test_a_security_update_with_a_trailing_group_still_becomes_a_finding(monkeypatch):
    """Eșecul pe care îl previne: linia se parsează, dar constatarea nu mai ajunge
    în panou — sau ajunge cu versiunea reparată luată din grupul greșit.

    Pe gazda măsurată pe 14 septembrie niciuna dintre cele 15 linii nu era din
    depozitul de securitate, deci drumul de la potrivire la constatare nu e
    acoperit de acea fixtură. Linia de aici e tot măsurată, de pe aceeași gazdă,
    cu două zile înainte: e una dintre cele zece pe care scanarea din 12
    septembrie nu le-a putut citi, iar actualizarea ei de securitate pentru
    `libc6-dev` n-a devenit niciodată constatare din cauza asta.
    """
    _apt_host(monkeypatch, out=(
        "NOTE: This is only a simulation!\n"
        + _APT_REAL_NOBLE
        + _APT_REAL_SECURITY_WITH_TRAILING_GROUP + "\n"))
    findings, error, _ = _run(os_packages.scan("debian"))

    assert error is None, error
    libc = next(f for f in findings if f["package"] == "libc6-dev")
    assert libc["installed_version"] == "2.39-0ubuntu8.8"
    assert libc["fixed_version"] == "2.39-0ubuntu8.9"
    assert libc["raw"]["arch"] == "amd64"
    # Ambele origini, în ordinea în care le-a scris apt: dacă parsarea ar tăia
    # una, `_SECURITY_POCKET` ar putea rămâne fără buzunarul care contează.
    assert libc["raw"]["origins"] == (
        "Ubuntu:24.04/noble-security, Ubuntu:24.04/noble-updates")
    # Restul fixturei măsurate e din `noble-updates` și din depozitul Docker.
    # Constatarea trebuie să fie singura: o listă de actualizări obișnuite
    # prezentate ca fiind de securitate e zgomotul după care operatorul nu mai
    # citește niciuna.
    assert [f["package"] for f in findings] == ["libc6-dev"]


def test_the_tolerance_does_not_accept_anything_else_after_the_parenthesis(monkeypatch):
    """Eșecul pe care îl previne: toleranța pentru lista de pachete rupte lărgită
    până acceptă orice coadă, adică exact garda care a prins forma asta.

    O coadă necunoscută după paranteză poate purta orice — inclusiv un al doilea
    câmp de origine. Dacă ar fi ignorată în tăcere, scanarea ar raporta o listă
    mai scurtă, iar `mark_resolved_absent` ar închide constatările liniilor
    neînțelese.
    """
    _apt_host(monkeypatch, out=(
        "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 "
        "Ubuntu:24.04/noble-security [amd64])\n"
        "Inst ceva-nou [1.0] (2.0 Ubuntu:24.04/noble-security [amd64]) ceva-necunoscut\n"))
    findings, error, _ = _run(os_packages.scan("debian"))
    assert findings == []
    assert error and "nu au forma așteptată" in error
    assert "ceva-necunoscut" in error


def test_the_tolerance_accepts_exactly_one_trailing_group():
    """Eșecul pe care îl previne: toleranța lărgită de la „exact un grup gol de
    paranteze drepte" la „orice coadă de paranteze drepte", adică fix garda pe
    care se sprijină toată schimbarea asta.

    Cardinalitatea E linia de apărare, nu forma `[...]`. Testul de mai sus
    hrănește doar cozi care nu sunt paranteze, deci fixează forma și lasă
    numărul liber: cu `?` devenit `*`, sau cu clasa de caractere lărgită ca
    grupul să înghită și `]`, o linie cu două grupuri e acceptată în tăcere. O
    coadă necunoscută poate purta orice — un al doilea câmp de origine inclusiv
    —, iar ce s-ar pierde atunci nu e o linie, ci deosebirea dintre o
    actualizare de securitate și una obișnuită, pe o linie care n-ar mai fi
    refuzată zgomotos.
    """
    # Două grupuri. Acceptată dacă `?` devine `*`, dar și dacă `[^\]]*` devine
    # `.*` (un singur grup care înghite `] [`).
    assert not os_packages._APT_INST.match(
        "Inst foo [1] (2 Ubuntu:24.04/noble-updates [all]) [] []")

    # Un singur grup, dar cu `]` înăuntru. Acceptată DOAR dacă se lărgește clasa
    # de caractere — separat de cel de sus fiindcă acela nu deosebește cele două
    # lărgiri între ele, iar o singură aserțiune ar spune care, nu că sunt două.
    assert not os_packages._APT_INST.match(
        "Inst foo [1] (2 Ubuntu:24.04/noble-updates [all]) [bar]]")

    # Un grup NEÎNCHIS. Acceptat dacă `\]` de la capătul grupului devine `\]?` —
    # o lărgire care, până la aserțiunea asta, nu pica niciun test din fișier: o
    # coadă trunchiată ar fi fost înghițită în tăcere, deși nimeni n-a citit ce
    # era în ea. Perechea ei, `\s*` → `\s+`, e o STRÂMTARE — singurul lucru pe
    # care-l poate face e să respingă zgomotos linia măsurată, care e deja
    # fixată mai jos —, deci nu-i trebuie aserțiune proprie.
    assert not os_packages._APT_INST.match(
        "Inst foo [1] (2 Ubuntu:24.04/noble-updates [all]) [bar")

    # Și forma pe care toleranța chiar o acceptă, măsurată pe gazdă: fără ea,
    # testul ar trece la fel de bine cu o expresie care respinge tot.
    assert os_packages._APT_INST.match(_APT_REAL_WITH_TRAILING_GROUP)


# --- ce ține apt în /var/lib/apt/lists, măsurat -----------------------------
# Listarea completă a directorului, de pe aceeași gazdă Ubuntu 24.04.4 LTS, pe
# 14 septembrie 2026: `LC_ALL=C ls -1A /var/lib/apt/lists | LC_ALL=C sort`.
# Ordinea e a gazdei (sortarea numelor REALE), deci nu e alfabetică pe numele de
# aici.
#
# E fixată din același motiv pentru care sunt fixate liniile `Inst`: câte
# indexuri are gazda și câte dintre ele sunt de securitate s-a scris de mână în
# comentarii și a fost greșit de două ori la rând. O cifră dintr-un paragraf nu
# se poate reverifica; o listă de nume da. Testul de mai jos nu citește niciun
# număr din proză — le derivă rulând chiar regula codului (`_apt_index_state`)
# peste fixtură, deci dacă regula se schimbă, testul se mută cu ea în loc să
# rămână în urmă.
#
# NUMELE OGLINZILOR SUNT ÎNLOCUITE; restul fiecărui nume e verbatim. Că fixtura
# nu e o copie literală stă scris aici tocmai ca să n-o citească nimeni drept
# una: repository-ul e public, iar oglinzile din care trage gazda spun de unde
# se aprovizionează ea. S-a păstrat tot ce cântărește în regulă — numărul de
# intrări, cele DOUĂ oglinzi care poartă fiecare cele patru componente
# `noble-security`, despărțirea dintre ce e de securitate și ce nu, sufixul
# `_Packages` pe care codul se sprijină — și, dinadins, faptul că una dintre
# oglinzi are `security` chiar în numele de gazdă: regula se potrivește pe
# NUMELE FIȘIERULUI, nu pe numele buzunarului, iar fixtura trebuie să poată
# arăta asta.
#
# SCRISĂ PE COLOANE: fiecare `_` din numele real e un spațiu aici, iar testul
# reface numele cu `"_".join(...)`. Nu e o preferință de așezare în pagină. Un
# nume de index apt e, după punctul din numele de gazdă, o înșiruire neîntreruptă
# de 60+ de caractere din alfabetul base64url — cu literă mică, literă mare și
# cifră în ea, adică exact compoziția pe care o caută garda din
# `tests/security/test_repo_is_sanitised.py`, care o raportează — pe drept, după
# formă — drept posibilă valoare generată scăpată într-un depozit public.
# Alternativa ar fi fost o scutire pe fișier în chiar garda aia, adică o gaură
# numită într-o apărare, pentru niște nume care nu sunt secrete. Despicarea nu
# schimbă măsurătoarea: numele se citește pe orizontală la fel de bine, iar ce
# rulează testul sunt numele refăcute, nu coloanele.
_APT_REAL_LISTS_ENTRIES = """\
mirror-one.example.invalid ubuntu dists noble-backports InRelease
mirror-one.example.invalid ubuntu dists noble-backports main binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble-backports main cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble-backports main dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble-backports main i18n Translation-en
mirror-one.example.invalid ubuntu dists noble-backports multiverse binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble-backports multiverse cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble-backports multiverse dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble-backports multiverse i18n Translation-en
mirror-one.example.invalid ubuntu dists noble-backports restricted cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble-backports restricted dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble-backports universe binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble-backports universe cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble-backports universe dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble-backports universe i18n Translation-en
mirror-one.example.invalid ubuntu dists noble-updates InRelease
mirror-one.example.invalid ubuntu dists noble-updates main binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble-updates main cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble-updates main dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble-updates main i18n Translation-en
mirror-one.example.invalid ubuntu dists noble-updates multiverse binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble-updates multiverse cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble-updates multiverse dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble-updates multiverse i18n Translation-en
mirror-one.example.invalid ubuntu dists noble-updates restricted binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble-updates restricted cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble-updates restricted dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble-updates restricted i18n Translation-en
mirror-one.example.invalid ubuntu dists noble-updates universe binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble-updates universe cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble-updates universe dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble-updates universe i18n Translation-en
mirror-one.example.invalid ubuntu dists noble InRelease
mirror-one.example.invalid ubuntu dists noble main binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble main cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble main dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble main i18n Translation-en
mirror-one.example.invalid ubuntu dists noble multiverse binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble multiverse cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble multiverse dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble multiverse i18n Translation-en
mirror-one.example.invalid ubuntu dists noble restricted binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble restricted cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble restricted i18n Translation-en
mirror-one.example.invalid ubuntu dists noble universe binary-amd64 Packages
mirror-one.example.invalid ubuntu dists noble universe cnf Commands-amd64
mirror-one.example.invalid ubuntu dists noble universe dep11 Components-amd64.yml.gz
mirror-one.example.invalid ubuntu dists noble universe i18n Translation-en
auxfiles
vendor-repo.example.invalid linux ubuntu dists noble InRelease
vendor-repo.example.invalid linux ubuntu dists noble stable binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-backports InRelease
mirror-two.example.invalid ubuntu dists noble-backports main binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-backports main cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-backports main dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-backports main i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-backports multiverse binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-backports multiverse cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-backports multiverse dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-backports multiverse i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-backports restricted cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-backports restricted dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-backports universe binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-backports universe cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-backports universe dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-backports universe i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-security InRelease
mirror-two.example.invalid ubuntu dists noble-security main binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-security main cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-security main dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-security main i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-security multiverse binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-security multiverse cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-security multiverse dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-security multiverse i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-security restricted binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-security restricted cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-security restricted dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-security restricted i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-security universe binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-security universe cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-security universe dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-security universe i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-updates InRelease
mirror-two.example.invalid ubuntu dists noble-updates main binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-updates main cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-updates main dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-updates main i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-updates multiverse binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-updates multiverse cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-updates multiverse dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-updates multiverse i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-updates restricted binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-updates restricted cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-updates restricted dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-updates restricted i18n Translation-en
mirror-two.example.invalid ubuntu dists noble-updates universe binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble-updates universe cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble-updates universe dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble-updates universe i18n Translation-en
mirror-two.example.invalid ubuntu dists noble InRelease
mirror-two.example.invalid ubuntu dists noble main binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble main cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble main dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble main i18n Translation-en
mirror-two.example.invalid ubuntu dists noble multiverse binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble multiverse cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble multiverse dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble multiverse i18n Translation-en
mirror-two.example.invalid ubuntu dists noble restricted binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble restricted cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble restricted i18n Translation-en
mirror-two.example.invalid ubuntu dists noble universe binary-amd64 Packages
mirror-two.example.invalid ubuntu dists noble universe cnf Commands-amd64
mirror-two.example.invalid ubuntu dists noble universe dep11 Components-amd64.yml.gz
mirror-two.example.invalid ubuntu dists noble universe i18n Translation-en
lock
partial
security-mirror.example.invalid ubuntu dists noble-security InRelease
security-mirror.example.invalid ubuntu dists noble-security main binary-amd64 Packages
security-mirror.example.invalid ubuntu dists noble-security main cnf Commands-amd64
security-mirror.example.invalid ubuntu dists noble-security main dep11 Components-amd64.yml.gz
security-mirror.example.invalid ubuntu dists noble-security main i18n Translation-en
security-mirror.example.invalid ubuntu dists noble-security multiverse binary-amd64 Packages
security-mirror.example.invalid ubuntu dists noble-security multiverse cnf Commands-amd64
security-mirror.example.invalid ubuntu dists noble-security multiverse dep11 Components-amd64.yml.gz
security-mirror.example.invalid ubuntu dists noble-security multiverse i18n Translation-en
security-mirror.example.invalid ubuntu dists noble-security restricted binary-amd64 Packages
security-mirror.example.invalid ubuntu dists noble-security restricted cnf Commands-amd64
security-mirror.example.invalid ubuntu dists noble-security restricted dep11 Components-amd64.yml.gz
security-mirror.example.invalid ubuntu dists noble-security restricted i18n Translation-en
security-mirror.example.invalid ubuntu dists noble-security universe binary-amd64 Packages
security-mirror.example.invalid ubuntu dists noble-security universe cnf Commands-amd64
security-mirror.example.invalid ubuntu dists noble-security universe dep11 Components-amd64.yml.gz
security-mirror.example.invalid ubuntu dists noble-security universe i18n Translation-en
"""

#: Pe gazdă astea două sunt DIRECTOARE, nu fișiere (`auxfiles` și `partial`,
#: al lui apt). Recreate ca directoare ca fixtura să semene cu gazda, nu
#: fiindcă vreo aserțiune ar depinde de asta: `_apt_index_state` le exclude
#: deja prin `"_Packages" in p.name`, deci un filtru `is_file()` adăugat
#: peste ar fi o operație nulă și aici, și pe gazdă. Verificat: adăugarea lui
#: lasă toată suita verde.
_APT_REAL_LISTS_SUBDIRS = ("auxfiles", "partial")


def test_the_index_counts_come_from_the_measured_directory(tmp_path, monkeypatch):
    """Eșecul pe care îl previne: poarta care refuză „curat" fără index de
    securitate, explicată de o cifră scrisă de mână — și apoi potrivită pe cifră.

    `security_indexes == 0` e singurul lucru care deosebește o gazdă care nu
    primește deloc actualizări de securitate de una obișnuită, adică cel mai
    periculos zero din panou. Ca să fie de crezut, poarta a fost însoțită într-un
    comentariu de numărul de indexuri de pe gazdă — număr greșit de două ori la
    rând (patru, când pe gazdă sunt opt). Cine ar potrivi regula pe cifra din
    comentariu ar strica fix poarta, și ar strica-o în direcția tăcută.

    Aici nu mai e nicio cifră de crezut pe cuvânt: numele sunt măsurate și
    fixate, iar numerele le calculează codul însuși peste ele.
    """
    names = ["_".join(ln.split())
             for ln in _APT_REAL_LISTS_ENTRIES.splitlines() if ln.strip()]
    assert len(names) == 135, (
        "fixtura măsurată s-a scurtat; un test rămas fără date de rulat trece "
        "fără să verifice nimic")
    assert len(set(names)) == len(names), "nume duplicate în fixtură"

    for name in names:
        if name in _APT_REAL_LISTS_SUBDIRS:
            (tmp_path / name).mkdir()
        else:
            (tmp_path / name).write_bytes(b"")
    monkeypatch.setattr(os_packages, "APT_LISTS_DIR", tmp_path)

    total, security, newest, error = os_packages._apt_index_state()
    assert error is None, error
    assert newest is not None, "niciun mtime citit dintr-un director plin"

    # Cele două cifre, derivate de cod din fixtură. Legate și de ce numără
    # regula, nu doar de un număr: dacă filtrul se lărgește (intrările care nu
    # sunt `_Packages` încep să conteze) sau se strâmtează, cele două laturi ale
    # egalității se depărtează, oricare ar fi cifra din dreapta.
    indexes = [n for n in names if "_Packages" in n]
    security_names = sorted(
        n for n in indexes if os_packages._SECURITY_POCKET in n.lower())
    assert len(indexes) == total == 31
    assert len(security_names) == security == 8

    # Forma pe care sanitizarea avea voie s-o atingă cel mai puțin: cele opt
    # nume numărate ca „de securitate" vin de la DOUĂ oglinzi, cu aceleași patru
    # componente fiecare. O fixtură turtită la o singură oglindă ar tot da 8 din
    # aserțiunea de sus, dar n-ar mai semăna cu gazda măsurată.
    assert len({n.split("_ubuntu_dists_")[0] for n in security_names}) == 2

    # Și fiecare dintre cele opt e chiar un index din buzunarul de securitate —
    # aserțiunea asta stă ÎNAINTEA despicării de mai jos dinadins, ca un nume
    # care nu-l conține să spună asta, nu să iasă cu `IndexError` din despicare.
    assert all("_noble-security_" in n for n in security_names)
    assert {n.split("_noble-security_")[1].split("_")[0]
            for n in security_names} == {
        "main", "multiverse", "restricted", "universe"}

    # Regula se uită la NUMELE FIȘIERULUI, deci potrivește și numele de gazdă al
    # oglinzii, nu doar buzunarul — iar pe gazda măsurată una dintre cele două
    # oglinzi chiar poartă `security` în numele ei. Azi nu iese niciun fals
    # pozitiv din asta: tot ce numără regula e un index `noble-security` real,
    # și aserțiunea de mai sus e cea care ar spune dacă vreodată nu mai e așa.
    assert any(os_packages._SECURITY_POCKET in n.split("_ubuntu_dists_")[0].lower()
               for n in security_names)


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
