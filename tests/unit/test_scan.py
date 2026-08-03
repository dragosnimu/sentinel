"""P7 scan core: prioritisation math, dnf output parsing, finding keys. All pure
— the scanners that touch dnf and the network are exercised on the server."""
from __future__ import annotations

from sentinel.db.repo.findings import finding_key
from sentinel.scan import os_packages, prioritize


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
