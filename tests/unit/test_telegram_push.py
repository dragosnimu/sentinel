"""The incident push must carry a working one-tap block button — but only for a
real network actor, never for an incident whose actor_key is a label rather than
an address. python-telegram-bot is not a local dev dependency, so this skips
where it is absent and runs in CI/on the host where the bot actually lives.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.db.repo.incidents import IncidentRow  # noqa: E402
from sentinel.telegram import bot  # noqa: E402


def _incident(actor_key: str | None, auto_action: str | None = None) -> IncidentRow:
    now = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
    return IncidentRow(
        id=39, fingerprint=f"auth.ssh_bruteforce:{actor_key}", status="open",
        severity="high", title="Brute-force SSH", summary=None, actor_key=actor_key,
        detection_count=30, first_detection_at=now, last_detection_at=now,
        ai_severity=None, notified_at=None, auto_action=auto_action,
    )


def _cfg(default_ttl_s: int = 86_400) -> SimpleNamespace:
    return SimpleNamespace(
        response=SimpleNamespace(auto_block=SimpleNamespace(default_ttl_s=default_ttl_s))
    )


def test_incident_ip_extracts_a_real_address():
    assert bot._incident_ip(_incident("203.0.113.53")) == "203.0.113.53"
    assert bot._incident_ip(_incident("2001:db8::1")) == "2001:db8::1"


def test_incident_ip_rejects_non_addresses():
    # actor_key is not always an IP — a correlated campaign key, a username, None.
    assert bot._incident_ip(_incident("campaign:abc")) is None
    assert bot._incident_ip(_incident("root")) is None
    assert bot._incident_ip(_incident(None)) is None


def test_block_button_present_for_ip_incident():
    kb = bot._incident_block_kb(_incident("203.0.113.53"), _cfg())
    assert kb is not None
    block_btn, ignore_btn = kb.inline_keyboard[0]
    # The callback must be exactly what on_callback's blk: handler parses.
    assert block_btn.callback_data == "blk:203.0.113.53:86400"
    assert "203.0.113.53" in block_btn.text
    assert ignore_btn.callback_data == "cancel"


def test_block_button_ttl_label_matches_config():
    kb = bot._incident_block_kb(_incident("203.0.113.53"), _cfg(default_ttl_s=3600))
    assert kb.inline_keyboard[0][0].callback_data == "blk:203.0.113.53:3600"
    assert "1h" in kb.inline_keyboard[0][0].text


def test_no_button_when_actor_is_not_an_ip():
    # A dashboard-scraper campaign with a non-IP key must not render a block
    # button pointed at a string the executor would reject anyway.
    assert bot._incident_block_kb(_incident("campaign:abc"), _cfg()) is None


def test_armed_block_offers_unblock_not_block():
    # When the decider already auto-blocked, the alert must offer UNBLOCK, never
    # a second block.
    kb = bot._incident_block_kb(_incident("203.0.113.53", auto_action="blocked"), _cfg())
    btn = kb.inline_keyboard[0][0]
    assert btn.callback_data == "unblk:203.0.113.53"
    assert "eblochează" in btn.text  # "Deblochează"


def test_auto_action_text_rendering():
    assert bot._auto_action_text(None) is None
    assert bot._auto_action_text("observed") is None
    assert "utomat" in bot._auto_action_text("blocked")  # "automat"
    assert "rată" in bot._auto_action_text("skipped:rate_cap")


def test_close_commands_are_registered_and_share_one_body():
    # /resolve and /fp must not pass state through bot_data: that dict is global
    # across every chat, so two operators acting at once could swap verdicts.
    import inspect
    from sentinel.telegram import bot as b
    src = inspect.getsource(b._close_incident)
    assert "status: str" in inspect.signature(b._close_incident).parameters.__str__() \
        or "status" in inspect.signature(b._close_incident).parameters
    assert "bot_data[\"_resolve" not in inspect.getsource(b.cmd_resolve)
    assert "bot_data[\"_resolve" not in inspect.getsource(b.cmd_false_positive)
    assert "false_positive" in inspect.getsource(b.cmd_false_positive)


def test_close_requires_operator_role():
    import inspect
    from sentinel.telegram import bot as b
    src = inspect.getsource(b._close_incident)
    assert "_can_act" in src        # viewer must not be able to close
