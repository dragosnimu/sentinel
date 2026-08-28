"""How the distribution family travels from the installer to the runtime.

There is exactly one detector, `distro_detect` in deploy/lib/distro.sh. It runs
at install time, install.sh renders its answer into sentinel.yaml, and Python
reads it from there. This file pins the joints in that chain, because each of
them can break without anything else noticing:

  * the template still asks for the value;
  * install.sh substitutes it from the variable the detector sets, and not from
    some other variable that happens to be in scope;
  * every value the detector can produce is a value the runtime accepts;
  * every value the runtime accepts selects a real scanner.

The third one is the joint that would fail silently. Adding a family to
distro.sh without teaching sentinel.constants about it produces a host whose
config the daemons refuse to load — after the install has reported success.
"""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.constants import PLATFORM_FAMILIES

REPO = Path(__file__).resolve().parents[2]
INSTALL = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")
DISTRO = (REPO / "deploy" / "lib" / "distro.sh").read_text(encoding="utf-8")
TMPL = (REPO / "deploy" / "config" / "sentinel.yaml.tmpl").read_text(encoding="utf-8")


def test_the_template_asks_for_the_family():
    """Without the key in the template, a fresh Ubuntu install writes a config
    with no family, the runtime falls back to rhel, and the host runs dnf."""
    assert re.search(r'^\s*family:\s*"@@PLATFORM_FAMILY@@"\s*$', TMPL, re.M), \
        "sentinel.yaml.tmpl has no `family: \"@@PLATFORM_FAMILY@@\"` line"


def test_the_installer_substitutes_the_family_from_the_detector():
    """A substitution from any other variable would be a second source of truth.

    In particular it must not come from preflight.env: resolve_config sources
    that file AFTER install.sh has run distro_detect, so a stale file left by an
    earlier run against another host would override the live answer.
    """
    assert "s|@@PLATFORM_FAMILY@@|${DISTRO_FAMILY}|g" in INSTALL, \
        ("@@PLATFORM_FAMILY@@ must be substituted from ${DISTRO_FAMILY}, the "
         "variable distro_detect sets")


def test_the_installer_refuses_an_undetected_family_before_writing_configs():
    """If distro_detect fails and the installer carries on, the template gets an
    empty family, the config is rejected at load, and the failure surfaces only
    when a service will not start — long after the install said it worked."""
    assert re.search(r"^distro_detect \|\| die", INSTALL, re.M)
    assert re.search(r"^distro_supported \|\| die", INSTALL, re.M)


def test_every_family_the_detector_can_set_is_one_the_runtime_accepts():
    """The silent break: `DISTRO_FAMILY="suse"` added to distro.sh, install
    succeeds, and every daemon then refuses the config it was just handed."""
    assigned = {
        value for value in re.findall(r'DISTRO_FAMILY="([^"]*)"', DISTRO) if value
    }
    assert assigned, "no DISTRO_FAMILY assignments found — has distro.sh moved?"
    unknown = assigned - set(PLATFORM_FAMILIES)
    assert not unknown, (
        f"distro.sh can set platform.family to {sorted(unknown)}, which "
        f"sentinel.constants.PLATFORM_FAMILIES ({list(PLATFORM_FAMILIES)}) "
        "rejects. The install would succeed and the runtime would not start."
    )


# What install.sh feeds each placeholder, so the rendered file below is the file
# a real install writes rather than an approximation of it.
_RENDER_VALUES = {
    "@@DOMAIN@@": "sentinel.example.test",
    "@@HOSTNAME@@": "host.example.test",
    "@@NGINX_MODE@@": "dedicated",
    "@@PUBLIC_PORT@@": "8443",
    "@@IFACE@@": "eth0",
    "@@BPF_FILTER@@": "",
    "@@SURICATA_ENABLED@@": "true",
    "@@AUDITD_ENABLED@@": "true",
    "@@TELEGRAM_CHAT_ID@@": "123456",
    "@@EXTRA_ALLOWLIST@@": "",
}


def _render(family: str) -> str:
    text = TMPL.replace("@@PLATFORM_FAMILY@@", family)
    for token, value in _RENDER_VALUES.items():
        text = text.replace(token, value)
    leftover = set(re.findall(r"@@[A-Z_]+@@", text))
    assert not leftover, (
        f"the template gained placeholders this test does not render: {leftover}. "
        "Add them here, or the rest of this file is checking a stale file.")
    return text


def test_the_render_helper_covers_every_family_this_file_claims_to_check():
    """A parametrised list that came out empty is one of the three tests this
    repository has already had pass while checking nothing. If PLATFORM_FAMILIES
    were ever empty, every loop below would be a no-op and stay green."""
    assert len(PLATFORM_FAMILIES) >= 2, list(PLATFORM_FAMILIES)


def test_the_rendered_config_loads_and_carries_the_family(tmp_path):
    """The end of the chain, checked as an effect rather than as an intention.

    A `family:` line that renders into something the loader rejects would pass
    every string check above and still stop every daemon on the host — after the
    installer had reported success. So render the template the way install.sh
    does and load it with the real loader.
    """
    from sentinel.config import load_config

    for family in PLATFORM_FAMILIES:
        path = tmp_path / f"sentinel-{family}.yaml"
        path.write_text(_render(family), encoding="utf-8", newline="")
        cfg = load_config(path)
        assert cfg.platform.family == family


def test_the_rendered_config_selects_a_real_scanner(tmp_path):
    """Loading is not enough: the value has to reach the scanner selection. A
    family that loads but selects nothing is a host that scans nothing."""
    from sentinel.config import load_config
    from sentinel.scan.os_packages import UNKNOWN_SCANNER, scanner_for

    expected = {"rhel": "dnf", "debian": "apt"}
    for family in PLATFORM_FAMILIES:
        path = tmp_path / f"sentinel-{family}.yaml"
        path.write_text(_render(family), encoding="utf-8", newline="")
        cfg = load_config(path)
        name = scanner_for(cfg.platform.family)
        assert name != UNKNOWN_SCANNER
        assert name == expected[family]


def test_every_family_the_runtime_accepts_has_a_scanner():
    """A family with no OS-package scanner is a host that reports zero
    vulnerabilities forever, which is what this whole change exists to stop."""
    from sentinel.scan.os_packages import SCANNER_BY_FAMILY, UNKNOWN_SCANNER

    for family in PLATFORM_FAMILIES:
        assert family in SCANNER_BY_FAMILY, f"{family} selects no scanner"
        assert SCANNER_BY_FAMILY[family] != UNKNOWN_SCANNER


def test_the_rhel_scanner_is_still_called_dnf():
    """Continuitatea cheii pe care o citește operatorul, nu doar existența ei.

    `check_last_scan` raportează sub `scan:last:{scanner}`, iar `selfcheck_state`
    de pe gazda de producție are cheia `scan:last:dnf` cu istoric din 21 august
    2026. Redenumit — în `os_packages`, `os-packages`, orice — vechiul rând ar fi
    reconciliat afară de `_reconcile_state` și în locul lui ar apărea unul cu
    `since = now()`: aceeași pierdere de istoric prinsă acum trei zile la
    `audit:records`.
    """
    from sentinel.scan.os_packages import scanner_for

    assert scanner_for("rhel") == "dnf"
