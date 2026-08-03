"""Approval tokens: the gate between "a plan exists" and "the machine changed".

A Telegram button lives in a chat history forever and can be tapped by anyone
who can see that chat, at any time. So the button must not BE the authority —
these tests pin the properties that make it merely a reference to one.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from sentinel.db.repo import approvals

REPO = Path(__file__).resolve().parents[2]
APPROVALS = (REPO / "sentinel" / "db" / "repo" / "approvals.py").read_text(encoding="utf-8")
FLOW = (REPO / "sentinel" / "telegram" / "patch_flow.py").read_text(encoding="utf-8")
BOT = (REPO / "sentinel" / "telegram" / "bot.py").read_text(encoding="utf-8")


def run(c):
    return asyncio.run(c)


class _StubDB:
    """Records SQL so the atomicity of consume() can be asserted on the query
    itself — which is where the property actually lives."""

    def __init__(self, row=None):
        self.sql: list[str] = []
        self.args: list[tuple] = []
        self.row = row

    async def execute(self, sql, *a):
        self.sql.append(sql); self.args.append(a); return "OK"

    async def fetchrow(self, sql, *a):
        self.sql.append(sql); self.args.append(a); return self.row

    async def fetch(self, sql, *a):
        self.sql.append(sql); self.args.append(a); return []


# --- the token itself -------------------------------------------------------
def test_tokens_are_unguessable_and_fit_a_callback():
    seen = {approvals.new_token() for _ in range(500)}
    assert len(seen) == 500                     # no collisions
    for t in list(seen)[:20]:
        assert len(t) >= 20                     # ~144 bits of entropy
        # Telegram caps callback_data at 64 bytes; the prefix costs 5.
        assert len(t) <= 58
        assert re.fullmatch(r"[A-Za-z0-9_-]+", t)


# --- single use, atomically -------------------------------------------------
def test_consume_checks_and_spends_in_one_statement():
    """Read-then-write would let a double tap, a retried callback, or two
    operators all pass the check before any of them wrote."""
    body = _func(APPROVALS, "consume")
    assert "UPDATE approval_tokens" in body
    assert "SET used_at = now()" in body
    assert "AND used_at IS NULL" in body        # the check is IN the update
    assert "RETURNING" in body
    # There must be no separate SELECT before it.
    assert "SELECT" not in body.split("UPDATE approval_tokens")[0]


def test_consume_binds_purpose_chat_and_expiry():
    body = _func(APPROVALS, "consume")
    assert "AND purpose = $2" in body           # a block token cannot approve a patch
    assert "chat_id = $3" in body               # nor one from another chat
    assert "expires_at > now()" in body


def test_a_used_token_returns_none():
    db = _StubDB(row=None)                      # UPDATE matched nothing
    assert run(approvals.consume(db, "t", purpose="patch_apply",
                                 chat_id=1, used_by="x")) is None


def test_issue_stores_the_plan_hash():
    """Binding the hash is what makes a regenerated plan kill every button that
    was already sent: the bytes changed, so no old token matches."""
    db = _StubDB()
    run(approvals.issue(db, purpose="patch_apply", plan_id=7, plan_hash="abc",
                        created_by="test"))
    assert "plan_hash" in db.sql[0]
    assert "abc" in db.args[0]


def test_revoking_kills_only_unused_tokens():
    body = _func(APPROVALS, "revoke_for_plan")
    assert "used_at IS NULL" in body
    assert "plan_id = $1" in body


# --- the two-stage conversation --------------------------------------------
def test_first_tap_applies_nothing():
    body = _func(FLOW, "on_stage1")
    assert "run_plan" not in body               # stage 1 cannot execute
    assert "approvals.issue" in body            # it only issues stage 2
    assert "stage=2" in body


def test_second_screen_restates_the_consequences():
    """"Are you sure" is only a gate if the second screen carries information
    the first did not."""
    body = _func(FLOW, "on_stage1")
    assert "Downtime estimat" in body
    assert "IREVERSIBIL" in body                # warned when reversible is false
    assert "REBOOT" in body


def test_stage2_rejects_a_stage1_token():
    body = _func(FLOW, "on_stage2")
    assert "second.stage != 2" in body


def test_stage1_refuses_when_the_plan_changed_underneath():
    body = _func(FLOW, "on_stage1")
    assert "row.plan_hash != first.plan_hash" in body
    assert "s-a schimbat" in body


def test_approval_passes_the_hash_to_the_repo():
    body = _func(FLOW, "on_stage2")
    assert "expected_hash=second.plan_hash" in body


def test_applying_revokes_every_other_button():
    body = _func(FLOW, "on_stage2")
    assert "revoke_for_plan" in body


def test_rollback_failure_is_shouted_not_summarised():
    body = _func(FLOW, "on_stage2")
    assert "ROLLBACK-UL A EȘUAT" in body
    assert "restore.sh" in body                 # and tells them the way back


def test_dry_run_needs_no_token_but_still_needs_a_role():
    dry = _func(FLOW, "on_dry_run")
    assert "consume" not in dry                 # seeing is not changing
    assert 'mode="dry_run"' in dry
    # The role check lives once, in the router, before any branch.
    router = _func(BOT, "on_patch_callback")
    assert "_can_act" in router
    idx_check = router.index("_can_act")
    idx_branch = router.index('prefix == "pap1"')
    assert idx_check < idx_branch


def test_patch_buttons_are_routed_before_the_generic_handler():
    """A token must never fall through to the block handler, which would treat
    it as an address."""
    patch_at = BOT.index('pattern=r"^(pap1:|pap2:|pdry:|prej:)"')
    generic_at = BOT.index('pattern=r"^(blk:|unblk:|cancel$)"')
    assert patch_at < generic_at


def _func(source: str, name: str) -> str:
    m = re.search(rf"^(?:async )?def {re.escape(name)}\(.*?(?=^(?:async )?def |\Z)",
                  source, re.S | re.M)
    assert m, f"function {name} not found"
    return m.group(0)
