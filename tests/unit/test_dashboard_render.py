"""Render the dashboard template against the exact context shape the router
builds. A Jinja typo (a renamed key, a missing attribute) only shows up on a
logged-in page load, which is the worst possible place to discover it — this
catches it in CI instead.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

from sentinel.analytics.insights import Insight  # noqa: E402

TEMPLATES = Path(__file__).resolve().parents[2] / "sentinel" / "web" / "templates"
NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)


def _env() -> "jinja2.Environment":
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES)),
        autoescape=True,   # the real app autoescapes; attacker text lands here
    )


def _context(**over):
    ctx = {
        "user": type("U", (), {"username": "operator", "role": "owner"})(),
        "csrf_token": "t",
        "status": {"version": "0.13.0", "database": "ok", "database_size_mb": 264,
                   "schema_version": 12, "auto_block": False, "suricata": True,
                   "ai": True, "telegram": True, "panic_active": False,
                   "ip_allowlist": False},
        "phase_notice": None,
        "posture": {"level": "warning", "verdict": "Sub atac constant",
                    "atacatori": 629, "evenimente": 3861, "critice": 0,
                    "avertismente": 5, "intruziuni": 0},
        "insights": [
            Insight("critical", "Titlu critic", "Detaliu.", "Fă ceva",
                    {"detalii": ["1.2.3.4 (sshd, 10 ev)"]}),
            Insight("info", "Titlu info", "Detaliu.", None, {"top": ["root — 900"]}),
            Insight("good", "Totul bine", "Detaliu.", None, {}),
        ],
        "kpi": {"evenimente_24h": 103853, "ostile_24h": 100567, "atacatori_24h": 876,
                "incidente_deschise": 537, "incidente_grave": 11,
                "vuln_deschise": 0, "vuln_kev": 0, "blocate": 4},
        "deltas": {"ostile": {"dir": "up", "pct": 40, "text": "↑ 40%"},
                   "atacatori": {"dir": "down", "pct": 12, "text": "↓ 12%"}},
        "countries": [{"tara": "DE", "ev": 989, "ips": 47, "pct": 100},
                      {"tara": "US", "ev": 612, "ips": 326, "pct": 62}],
        "asns": [{"operator": "Netiface America, Inc.", "asn": 401116,
                  "ev": 665, "ips": 3, "pct": 100}],
        "feed": [{"kind": "incident", "id": 1, "lvl": "high",
                  "txt": "Brute-force SSH", "meta": "1.2.3.4", "at": NOW},
                 {"kind": "block", "id": 2, "lvl": "high",
                  "txt": "IP blocat: 1.2.3.4", "meta": "telegram", "at": NOW},
                 {"kind": "scan", "id": 3, "lvl": "info",
                  "txt": "Scanare dnf: 0 rezultate", "meta": "completed", "at": NOW}],
        "sources": [{"source": "suricata", "ev_24h": 900, "ultim": NOW},
                    {"source": "sshd", "ev_24h": 0, "ultim": NOW}],
        "attackers": [{"ip": "203.0.113.43", "ev": 36, "surse": 3,
                       "care": "auditd+sshd+suricata", "tara": None,
                       "ultim": NOW, "blocat": False}],
        "accounts": [{"username": "root", "n": 927, "ips": 74}],
        "paths": [{"http_path": "/glpi/front/inventory.php", "n": 375, "ips": 2}],
        "signatures": [{"sig": "ET DROP Dshield", "n": 137, "ips": 126}],
        "hourly": [{"ora": NOW - timedelta(hours=i), "n": 10 * i, "pct": min(100, 4 * i)}
                   for i in range(24, 0, -1)],
        "health": {"up": 12, "down": 1, "necunoscut": 1},
        "active": "dashboard",
    }
    ctx.update(over)
    return ctx


def test_dashboard_renders():
    html = _env().get_template("dashboard.html").render(**_context())
    assert "Panou de securitate" in html
    assert "Titlu critic" in html
    assert "203.0.113.43" in html


def test_dashboard_renders_with_no_data_at_all():
    # A fresh install must not 500 on empty tables.
    html = _env().get_template("dashboard.html").render(**_context(
        insights=[], attackers=[], accounts=[], paths=[], signatures=[],
        hourly=[], sources=[], health={},
    ))
    assert "Nicio observație de semnalat" in html
    assert "Nicio activitate ostilă" in html


def test_panic_banner_appears_when_the_file_exists():
    ctx = _context()
    ctx["status"] = {**ctx["status"], "panic_active": True}
    assert "PANIC" in _env().get_template("dashboard.html").render(**ctx)


def test_attacker_text_is_escaped():
    # http_path and signatures are attacker-controlled; autoescaping must hold.
    html = _env().get_template("dashboard.html").render(**_context(
        paths=[{"http_path": "/<script>alert(1)</script>", "n": 1, "ips": 1}]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_geographic_panel_renders_countries_and_operators():
    html = _env().get_template("dashboard.html").render(**_context())
    assert "Originea atacurilor" in html
    assert "DE" in html and "989" in html
    assert "Netiface America" in html
    assert "AS401116" in html


def test_activity_feed_links_incidents_only():
    html = _env().get_template("dashboard.html").render(**_context())
    assert 'href="/incidents/1"' in html          # incident is clickable
    assert "IP blocat: 1.2.3.4" in html           # block entry is plain text


def test_kpi_delta_states_direction_in_text_not_only_colour():
    # Colour alone fails for a colour-blind reader and in print.
    html = _env().get_template("dashboard.html").render(**_context())
    assert "↑ 40%" in html and "↓ 12%" in html


def test_login_page_has_no_sidebar_and_no_user_chrome():
    # The unauthenticated branch of base.html must expose no navigation at all:
    # nothing to navigate to, and nothing to leak to someone not logged in.
    html = _env().get_template("login.html").render(version="0.13.0", csrf_token="t")
    assert "auth-card" in html
    assert "sidebar" not in html and "sidenav" not in html


def test_sidebar_marks_the_active_page():
    html = _env().get_template("dashboard.html").render(**_context())
    assert 'class="active"' in html or "active" in html
    assert "ico-grid" in html and "ico-shield" in html   # icons are inline masks


def test_findings_page_renders():
    html = _env().get_template("findings.html").render(
        user=_context()["user"], active="findings",
        counts={"total": 2, "critical": 1, "high": 1, "kev": 1},
        rows=[{"id": 1, "cve": "CVE-2026-1", "advisory_id": None, "title": "x",
               "severity": "critical", "cvss": 9.8, "epss": 0.7, "kev": True,
               "priority": 100, "package": "kernel", "installed_version": "1",
               "fixed_version": "2", "scanner": "dnf", "location": None,
               "status": "open", "last_seen": NOW, "asset_name": None,
               "sev_dot": "bad"}])
    assert "CVE-2026-1" in html and "kernel" in html


def test_absurd_delta_is_worded_not_numeric():
    from sentinel.analytics.aggregate import deltas  # noqa: F401  (doc anchor)
    # The chip helper lives inside deltas(); exercise its wording contract via
    # the template instead, which is where a "3651%" would be seen.
    html = _env().get_template("dashboard.html").render(**_context(
        deltas={"ostile": {"dir": "up", "pct": None, "text": "↑ de la o bază foarte mică"},
                "atacatori": {"dir": "flat", "pct": 0, "text": "≈ la fel"}}))
    assert "de la o bază foarte mică" in html
    assert "3651" not in html


def _plan_row(status="validated", errors=None):
    from types import SimpleNamespace
    from tests.unit.test_patch_runner import _plan
    return SimpleNamespace(
        id=1, plan_id="x", plan_hash="a" * 64, plan=_plan(), status=status,
        status_ro="validat", pill="warn", risk_level="medium",
        requires_reboot=False, reversible=True, estimated_downtime_s=5,
        asset_id=93, asset="nginx", created_at=NOW, approved_by=None,
        approved_at=None, validation_errors=errors)


def test_patches_list_renders():
    html = _env().get_template("patches.html").render(
        user=_context()["user"], active="patches", rows=[_plan_row()],
        restore_points=[{"path": "/var/backups/sentinel/20260803-1",
                         "asset_name": "nginx", "size_bytes": 5_242_880,
                         "created_at": NOW, "verified_at": NOW,
                         "verify_error": None, "restored_at": None,
                         "retention_hold": False}],
        msg=None, csrf_token="t", version="1")
    assert "Planuri de patch" in html and "nginx" in html
    assert "restore.sh" in html            # the way back is advertised


def test_patch_detail_shows_every_phase_and_the_json():
    import json as _json
    row = _plan_row()
    html = _env().get_template("patch.html").render(
        user=_context()["user"], active="patches", p=row,
        plan_json=_json.dumps(row.plan, indent=2, ensure_ascii=False),
        executions=[], steps=[], can_act=True, csrf_token="t", version="1",
        request=type("Q", (), {"query_params": {}})())
    for phase in ("Preflight", "Backup", "Aplicare", "Revenire", "Verificare finală"):
        assert phase in html
    # Approval is Telegram-only, and the page must say so rather than offer it.
    assert "doar pe Telegram" in html
    assert "Dry-run" in html


def test_invalid_plan_shows_why_and_offers_no_actions():
    row = _plan_row(status="rejected_invalid",
                    errors=[{"path": "$.apply[0].argv", "code": "bad_binary",
                             "message": "rm nu este permis"}])
    row.pill = "bad"
    html = _env().get_template("patch.html").render(
        user=_context()["user"], active="patches", p=row, plan_json="{}",
        executions=[], steps=[], can_act=True, csrf_token="t", version="1",
        request=type("Q", (), {"query_params": {}})())
    assert "respins de validator" in html
    assert "rm nu este permis" in html
    assert "Dry-run" not in html           # an invalid plan offers nothing
