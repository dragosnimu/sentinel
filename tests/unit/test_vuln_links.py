"""Vulnerability reference links, and the two ways they could go wrong.

A CVE identifier reaches this code from scanner output and from IDS signature
names. Both are strings the outside world influences, and both end up inside an
`href` — so the interesting tests here are the ones where no link is produced.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.intel import links

REPO = Path(__file__).resolve().parents[2]


# --- only real CVEs become URLs --------------------------------------------
@pytest.mark.parametrize("value", [
    "CVE-2021-44228",
    "cve-2021-44228",              # case is normalised, not rejected
    "CVE-2026-9538",
    "CVE-2021-4422800000",         # long sequence numbers are legal
])
def test_well_formed_ids_are_accepted(value):
    assert links.is_cve(value)
    assert links.cve_url(value).endswith(value.upper())


@pytest.mark.parametrize("value", [
    'CVE-2021-44228"><script>alert(1)</script>',
    "CVE-2021-44228 OR 1=1",
    "CVE-2021-44228/../../etc/passwd",
    "https://evil.example/CVE-2021-44228",
    "CVE-21-1",                    # malformed year and sequence
    "CVE-2021-",
    "", None, 42, ["CVE-2021-44228"],
])
def test_anything_else_gets_no_url(value):
    """An href built from unvalidated input is how a link goes somewhere else."""
    assert not links.is_cve(value)
    assert links.cve_url(value) is None
    assert links.cve_links(value) == []


def test_a_non_cve_is_shown_but_never_linked():
    out = links.cve_html('<img src=x onerror=alert(1)>')
    assert "<a " not in out
    assert "&lt;img" in out        # escaped, so it renders as text


# --- source order encodes what the operator actually needs ------------------
def test_redhat_comes_first_for_package_findings():
    """On AlmaLinux the question is backport status, not the upstream range.
    NVD reports the upstream version and will call a backported package
    vulnerable when it is not."""
    labels = [name for name, _ in links.cve_links("CVE-2026-9538", rpm=True)]
    assert labels[0] == "Red Hat"
    assert "NVD" in labels


def test_nvd_is_the_default_for_everything_else():
    labels = [name for name, _ in links.cve_links("CVE-2021-44228")]
    assert labels == ["NVD"]


def test_kev_link_appears_only_when_it_is_listed():
    """A link that is always present teaches you to ignore it."""
    assert "CISA KEV" not in dict(links.cve_links("CVE-2021-44228")).keys()
    assert "CISA KEV" in dict(links.cve_links("CVE-2021-44228", kev=True))


def test_every_url_is_https():
    for name, url in links.cve_links("CVE-2021-44228", rpm=True, kev=True):
        assert url.startswith("https://"), name


# --- pulling CVEs out of signature names ------------------------------------
def test_cves_are_found_inside_ids_signature_names():
    found = links.cves_in("ET EXPLOIT Apache log4j RCE Attempt CVE-2021-44228")
    assert found == ["CVE-2021-44228"]


def test_multiple_cves_keep_their_order_and_do_not_repeat():
    text = "CVE-2021-45046 follow-up to CVE-2021-44228, see also cve-2021-45046"
    assert links.cves_in(text) == ["CVE-2021-45046", "CVE-2021-44228"]


def test_no_cves_in_ordinary_text():
    assert links.cves_in("Brute-force SSH de la 203.0.113.5") == []
    assert links.cves_in(None) == []


# --- the web side -----------------------------------------------------------
def test_dashboard_links_do_not_leak_which_cves_this_host_has():
    """Without `noreferrer`, following a link tells NVD, Red Hat and CISA which
    page of this dashboard it came from — that is, that this host has that CVE
    open. A security dashboard should not disclose its findings by being read."""
    macro = (REPO / "sentinel" / "web" / "templates" / "_vuln.html").read_text(encoding="utf-8")
    assert macro.count("rel=\"noopener noreferrer\"") >= 3
    assert "target=\"_blank\"" in macro


def test_no_template_builds_a_vulnerability_url_by_hand():
    """Every reference goes through the macro, so the URL set is changed in one
    place. The first version of this had NVD hardcoded in findings.html and a
    bare identifier in every other template."""
    tpl_dir = REPO / "sentinel" / "web" / "templates"
    offenders = []
    for path in tpl_dir.glob("*.html"):
        if path.name == "_vuln.html":
            continue
        text = path.read_text(encoding="utf-8")
        for host in ("nvd.nist.gov", "access.redhat.com", "cisa.gov"):
            if host in text:
                offenders.append(f"{path.name}:{host}")
    assert not offenders, f"hardcoded reference URLs remain: {offenders}"


def test_the_pages_that_show_a_cve_import_the_macro():
    tpl_dir = REPO / "sentinel" / "web" / "templates"
    for name in ("findings.html", "patch.html", "incident.html", "incidents.html"):
        text = (tpl_dir / name).read_text(encoding="utf-8")
        assert '{% import "_vuln.html" as vuln %}' in text, name
        assert "vuln.cve_cell(" in text or "vuln.cve_refs(" in text, name


def test_templates_render_with_links(tmp_path):
    pytest.importorskip("jinja2")
    from sentinel.web.jinja import build_env

    macro = build_env().get_template("_vuln.html").module

    cell = str(macro.cve_cell("CVE-2026-9538", rpm=True, kev=True))
    assert "access.redhat.com" in cell and "nvd.nist.gov" in cell and "cisa.gov" in cell
    assert "noreferrer" in cell

    # A hostile "CVE" produces no anchor at all.
    hostile = str(macro.cve_cell('CVE-2021-1"><script>x</script>'))
    assert "<a " not in hostile and "<script>" not in hostile


# --- the Telegram side ------------------------------------------------------
def test_telegram_plan_message_links_its_cves():
    pytest.importorskip("telegram")
    from types import SimpleNamespace

    from sentinel.telegram import patch_flow
    row = SimpleNamespace(
        id=5, risk_level="low", plan_hash="x", reversible=True, requires_reboot=False,
        estimated_downtime_s=5,
        plan={"target": {"asset_name": "localhost", "stack": "os"},
              "vulnerabilities": [{"cve": "CVE-2026-9538"}],
              "apply": [], "backup": [], "rollback": []})
    text = patch_flow.format_plan(row)
    assert "access.redhat.com/security/cve/CVE-2026-9538" in text
    assert "<a href=" in text


def test_telegram_incident_alert_carries_references():
    pytest.importorskip("telegram")
    from datetime import datetime, timezone

    from sentinel.db.repo.incidents import IncidentRow
    from sentinel.telegram import bot

    now = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
    inc = IncidentRow(
        id=1, fingerprint="ids.suricata:1", status="open", severity="critical",
        title="ET EXPLOIT Apache log4j RCE CVE-2021-44228", summary=None,
        actor_key="203.0.113.5", detection_count=4, first_detection_at=now,
        last_detection_at=now, ai_severity=None, notified_at=None, auto_action=None)
    text = bot.format_incident(inc)
    assert "Referințe:" in text
    assert "nvd.nist.gov/vuln/detail/CVE-2021-44228" in text


def test_an_incident_without_a_cve_gets_no_references_line():
    """The line has to mean something when it appears."""
    pytest.importorskip("telegram")
    from datetime import datetime, timezone

    from sentinel.db.repo.incidents import IncidentRow
    from sentinel.telegram import bot

    now = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
    inc = IncidentRow(
        id=2, fingerprint="auth.ssh_bruteforce:1", status="open", severity="high",
        title="Brute-force SSH", summary="30 de încercări eșuate", actor_key="203.0.113.5",
        detection_count=30, first_detection_at=now, last_detection_at=now,
        ai_severity=None, notified_at=None, auto_action=None)
    assert "Referințe:" not in bot.format_incident(inc)


def test_a_signature_name_with_markup_cannot_become_live_html():
    """Signature names arrive from rule files and, through them, from whatever
    the rule author wrote. The alert is parse_mode=HTML."""
    pytest.importorskip("telegram")
    from datetime import datetime, timezone

    from sentinel.db.repo.incidents import IncidentRow
    from sentinel.telegram import bot

    now = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
    inc = IncidentRow(
        id=3, fingerprint="ids.suricata:2", status="open", severity="high",
        title='<a href="https://evil.example">click</a> CVE-2021-44228',
        summary=None, actor_key=None, detection_count=1, first_detection_at=now,
        last_detection_at=now, ai_severity=None, notified_at=None, auto_action=None)
    text = bot.format_incident(inc)
    # The hostile URL survives as TEXT — that is correct, and is the point:
    # every tag is escaped, so nothing in the title is a working link.
    assert "&lt;a href=" in text
    assert '<a href="https://evil.example' not in text
    # The only live anchors in the message are the ones this code built.
    import re as _re
    for href in _re.findall(r'<a href="([^"]+)"', text):
        assert href.startswith(("https://nvd.nist.gov/", "https://access.redhat.com/",
                                "https://www.cisa.gov/")), href
    # And the real CVE still gets its reference.
    assert "nvd.nist.gov" in text
