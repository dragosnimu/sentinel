"""The traffic light in the Telegram announcements.

Two messages carry it: the existing "new vulnerabilities" one (now with a colour on
each row) and the new "became red" one. What goes wrong for the operator if they
are wrong:

  * a message that says "became red" about something that was never assessed, or
    twice — the tap the operator asked not to open;
  * a KEV row painted red when the tree says Track (or the reverse), or a row with
    no data painted green;
  * a message that Telegram refuses (400) because of a character in a package
    name, losing the one alert that mattered.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from sentinel.scan import announce


def run(coro):
    return asyncio.run(coro)


def _finding(**over):
    base = {"cve": "CVE-2026-0001", "severity": "high", "package": "openssl",
            "installed_version": "3.0.1", "fixed_version": "3.0.2",
            "kev": False, "priority": 50}
    base.update(over)
    return base


def _red(**over):
    base = {"id": 7, "cve": "CVE-2025-29927", "package": "next", "priority": 98,
            "risk": {"points": {"exploitation": {"value": "active", "basis": "epss"}},
                     "epss": {"p": 0.99225, "percentile": 0.99936},
                     "cvss": {"source": "trivy", "score": 9.1}}}
    base.update(over)
    return base


def _channel(monkeypatch, *, ok=True):
    calls: list[str] = []

    async def fake_send(token, chats, text, **kw):
        calls.append(text)
        return [SimpleNamespace(chat_id=c, ok=ok, describe=lambda: "refuzat") for c in chats]

    monkeypatch.setattr("sentinel.config.get_secrets", lambda: {"TELEGRAM_BOT_TOKEN": "t"})
    monkeypatch.setattr("sentinel.telegram.direct.send_to_chats", fake_send)
    return calls


def _cfg(announce_new=True):
    return SimpleNamespace(scan=SimpleNamespace(announce_new=announce_new),
                           telegram=SimpleNamespace(allowed_chat_ids=[1]),
                           hostname="gazda")


# ---------------------------------------------------------------------------
# the colour on each row of "new vulnerabilities"
# ---------------------------------------------------------------------------
def test_each_row_carries_its_colour():
    items = [_finding(cve=f"CVE-{c}", risk_color=c, priority=p)
             for c, p in (("red", 90), ("amber", 70), ("grey", 45), ("green", 10))]
    lines = {line.split("<code>")[1].split("</code>")[0]: line
             for line in announce.build_message(items, host="g").splitlines()
             if "<code>" in line}
    assert lines["CVE-red"].startswith("🔴")
    assert lines["CVE-amber"].startswith("🟡")
    assert lines["CVE-grey"].startswith("⚪")
    assert lines["CVE-green"].startswith("🟢")


def test_a_kev_row_keeps_its_flame_next_to_whatever_colour_the_tree_gave_it():
    """The tree can say Track for a KEV (partial impact, not automatable). The row
    must say both, not hide either."""
    msg = announce.build_message(
        [_finding(cve="CVE-KEV", kev=True, risk_color="green", priority=10)], host="g")
    row = [ln for ln in msg.splitlines() if "CVE-KEV" in ln][0]
    assert row.startswith("🟢 🔥")


def test_a_row_without_a_colour_keeps_the_old_marks():
    """Findings that never went through the risk pass (and the older tests) keep
    `🔴` for KEV and a bullet otherwise."""
    msg = announce.build_message([_finding(cve="CVE-A", kev=True), _finding(cve="CVE-B")],
                                 host="g")
    rows = [ln for ln in msg.splitlines() if "<code>" in ln]
    assert rows[0].startswith("🔴") and rows[1].startswith("•")


def test_an_unknown_colour_word_is_drawn_grey_not_blank():
    msg = announce.build_message([_finding(risk_color="purple")], host="g")
    assert [ln for ln in msg.splitlines() if "<code>" in ln][0].startswith("⚪")


# ---------------------------------------------------------------------------
# "became red"
# ---------------------------------------------------------------------------
def test_the_red_message_says_what_became_red_and_why():
    msg = announce.build_red_message([_red()], host="gazda")
    assert "1 vulnerabilitate a ajuns la „Acum”" in msg
    # The note names the state first and CISA's name in brackets, as everywhere else.
    assert "Acum (Act): decizia CISA SSVC cea mai urgentă" in msg
    assert "roșie" not in msg and "roșii" not in msg
    assert "<code>CVE-2025-29927</code>" in msg and "next" in msg
    assert "EPSS 99,2%" in msg and "CVSS 9,1 (trivy)" in msg
    assert "/vuln 7" in msg
    assert "o singură dată" in msg


def test_the_red_message_pluralises_and_orders_by_priority():
    msg = announce.build_red_message(
        [_red(cve="CVE-LOW", priority=81, id=1), _red(cve="CVE-HIGH", priority=99, id=2)],
        host="gazda")
    assert "2 vulnerabilități au ajuns la „Acum”" in msg
    assert msg.index("CVE-HIGH") < msg.index("CVE-LOW")


def test_the_red_message_is_bounded_and_counts_the_rest():
    items = [_red(cve=f"CVE-{i:04d}", id=i, priority=80 + i % 20) for i in range(30)]
    msg = announce.build_red_message(items, host="gazda")
    assert sum(1 for ln in msg.splitlines() if ln.startswith("🔴 <code>")) == announce.MAX_LISTED
    assert f"încă {30 - announce.MAX_LISTED}" in msg
    assert "30 vulnerabilități au ajuns la „Acum”" in msg


def test_the_red_message_survives_a_hostile_package_name():
    msg = announce.build_red_message(
        [_red(package="<img src=x onerror=1>", cve="CVE-A&B")], host="<b>h</b>")
    assert "<img" not in msg and "&lt;img" in msg
    assert "CVE-A&amp;B" in msg and "&lt;b&gt;h&lt;/b&gt;" in msg


def test_the_red_message_tolerates_a_risk_that_is_missing_or_odd():
    for risk in (None, {}, "x", {"cvss": "x", "points": 5}):
        msg = announce.build_red_message([_red(risk=risk)], host="g")
        assert "CVE-2025-29927" in msg


# ---------------------------------------------------------------------------
# delivery
# ---------------------------------------------------------------------------
def test_the_red_announcement_is_delivered_and_the_chats_are_counted(monkeypatch):
    calls = _channel(monkeypatch)
    assert run(announce.announce_red(_cfg(), [_red()])) == 1
    assert len(calls) == 1 and "CVE-2025-29927" in calls[0]


def test_a_refused_delivery_counts_zero_so_the_claim_can_be_released(monkeypatch):
    """`enrich` retracts its claim on the finding only when this returns 0. A 400
    from Telegram looks exactly like success if the caller checks only that the
    call came back."""
    _channel(monkeypatch, ok=False)
    assert run(announce.announce_red(_cfg(), [_red()])) == 0


def test_nothing_to_announce_and_a_switched_off_channel_send_nothing(monkeypatch):
    calls = _channel(monkeypatch)
    assert run(announce.announce_red(_cfg(), [])) == 0
    assert run(announce.announce_red(_cfg(announce_new=False), [_red()])) == 0
    assert calls == [], "the switch was ignored"


def test_the_red_message_names_its_instance(monkeypatch):
    """Every direct send carries the instance line (two Sentinels once alerted the
    same chat for 19 hours without saying which machine spoke)."""
    calls = _channel(monkeypatch)
    cfg = _cfg()
    cfg.instance_label = "productie"
    run(announce.announce_red(cfg, [_red()]))
    assert calls and calls[0].startswith("<i>Instanță: productie"), calls[0][:80]
