"""The untrusted side of the approval: which commands are registered, how the
operator is asked, and that every real call names the step it replays.

The executor (root) runs a real patch step only if its argv is, byte for byte, step N
of a plan an operator signed for. Everything here is about the OTHER end of that
contract - `sentinel/patch/approval.py`, the runner, the checks and the Telegram flow -
and about the one failure that end can cause even when the executor is right: an index
that points at the wrong command, which the executor refuses halfway through an apply,
with the machine half-changed and the rollback refused too.

The strongest tests here run the real executor operations in-process behind the
client's interface (`_Loopback`): the sentinel side asks, the operator's own tool signs,
the executor's own code verifies and enforces. Nothing about the approval is faked
except the key's location and the processes the executor would start.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from types import SimpleNamespace
from typing import Any

import pytest

import commands
import policy
from _approval_support import KEY, enrol_key, sign, tool
from sentinel.errors import ExecutorRejected
from sentinel.patch import approval, runner
from sentinel.patch import backup as backup_mod
from sentinel.patch import checks as checks_mod
from sentinel.patch.validator import plan_hash
from tests.unit.test_patch_runner import _check, _FakeDB, _FakeExec, _plan


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# What the runner can be pointed at
# ---------------------------------------------------------------------------
class _Loopback:
    """The executor's own operations, behind the client's interface.

    `PolicyRefusal` becomes `ExecutorRejected` exactly as the socket server and the
    client turn it, so the sentinel side sees what it would see in production. The
    processes an operation would start (`_run`, the transient unit) are replaced by
    recorders; everything that DECIDES - the grammar, the registry, the HMAC, the
    binding - is the real code.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.ran: list[list[str]] = []
        self.transactions: list[list[str]] = []
        self.fail: set[str] = set()

    def call(self, op: str, *, socket_timeout_s: float | None = None, **args: Any) -> dict[str, Any]:
        self.calls.append({"op": op, **args})
        if op == "disk_free":
            return {"free": 50 * 1_048_576_000, "total": 1, "used_pct": 10}
        if op == "backup_create":
            return {"ok": True, "artifact": "/var/backups/sentinel/x/a.tar.zst", "sha256": "a" * 64, "size_bytes": 1}
        if op == "backup_finalize":
            return {"ok": True, "items": [{"artifact": "a.tar.zst", "sha256": "a" * 64, "size_bytes": 1,
                                           "is_archive": True}],
                    "manifest_path": "/var/backups/sentinel/x/manifest.json",
                    "restore_script": "/var/backups/sentinel/x/restore.sh", "total_bytes": 1}
        try:
            return commands.OPERATIONS[op](dict(args))
        except policy.PolicyRefusal as refusal:
            raise ExecutorRejected(f"refused: {refusal}") from None


@pytest.fixture
def loopback(monkeypatch, tmp_path):
    """An enrolled key, the real operations behind every client, and fake processes."""
    enrol_key(tmp_path, monkeypatch)
    policy._plan_registry.clear()
    policy._challenges.clear()
    client = _Loopback()
    for module in (runner, backup_mod, checks_mod, approval):
        monkeypatch.setattr(module, "_client", client)

    def fake_run(argv, timeout=30, cwd=None):
        client.ran.append(list(argv))
        out = ""
        if argv[:2] == ["systemctl", "is-active"]:
            out = "active"
        elif argv[:3] == ["rpm", "-q", "--qf"]:
            out = "0:1.20.1-14.el9\n"
        code = 1 if argv[0] in client.fail else 0
        return {"exit_code": code, "stdout": out, "stderr": "", "duration_ms": 1, "timed_out": False}

    def fake_transaction(argv, *, timeout_s, plan_hash, step_index, redact):
        # The one real thing: the approval is spent by the binding the runner sent.
        policy.consume_registered_step(plan_hash, step_index, argv)
        client.transactions.append(list(argv))
        code = 1 if argv[0] in client.fail or "dnf" in client.fail else 0
        return {"argv": argv, "cwd": None, "exit_code": code, "stdout": "", "stderr": "", "duration_ms": 1,
                "timed_out": False}

    monkeypatch.setattr(commands, "_run", fake_run)
    monkeypatch.setattr(commands.transient_unit, "run", fake_transaction)
    # The gate is tested on its own (test_executor_transient_unit.py); here it is open,
    # because the subject is the approval and not the host's permissions.
    monkeypatch.setattr(commands.transient_unit, "dry_run_report",
                        lambda: {"transient_unit": True, "refused_because": []})
    yield client
    policy._plan_registry.clear()
    policy._challenges.clear()


def _approve_through_the_tool(plan: dict[str, Any], plan_hash_: str, family: str = "rhel") -> list[list[str]]:
    """The operator's side of an approval, on the real code: the sentinel side builds
    the request, the TOOL parses it, recomputes the digest and signs, the executor
    registers. Returns the steps that were registered."""
    request = run(approval.challenge(plan, plan_hash_, family))
    parsed = tool.parse_request(request)
    token, _digest = tool.make_token(policy, KEY, parsed)
    run(approval.register(plan, plan_hash_, family, token))
    return parsed["steps"]


# ---------------------------------------------------------------------------
# flatten: the list of commands, and where each plan item sits in it
# ---------------------------------------------------------------------------
def test_flatten_lists_every_command_in_a_fixed_order_and_skips_what_sends_no_argv():
    """The registration and every call derive their indexes from this list; an item
    that moved would shift every index after it. disk_free and no_open_incident send
    no argv, so they have no entry - and no index to send."""
    flat = approval.flatten(_plan(), "rhel")
    assert flat.steps == [
        ["test", "-e", "/etc/nginx/nginx.conf"],
        ["rpm", "-q", "--qf", "%{EPOCH}:%{VERSION}-%{RELEASE}\\n", "nginx"],
        ["dnf", "-y", "update", "nginx"],
        ["systemctl", "is-active", "nginx.service"],
        ["systemctl", "is-active", "nginx.service"],
        ["dnf", "-y", "downgrade", "nginx-1.20.1-14.el9"],
    ]
    assert flat.ref("preflight", 0) is None, "disk_free sends no argv"
    assert [flat.ref("preflight", 1), flat.ref("preflight", 2), flat.ref("apply", 0),
            flat.ref("health_check", 0), flat.ref("post_verification", 0), flat.ref("rollback", 0)] == [
        0, 1, 2, 3, 4, 5]


def test_flatten_is_deterministic_and_does_not_depend_on_dict_order():
    plan = _plan()
    reordered = {key: plan[key] for key in reversed(list(plan))}
    assert approval.flatten(plan, "rhel").steps == approval.flatten(reordered, "rhel").steps


def test_the_digest_of_the_flattened_steps_is_the_executors_definition():
    flat = approval.flatten(_plan(), "rhel")
    assert policy.steps_digest(flat.steps) == approval._policy().steps_digest(flat.steps)


def test_a_check_that_cannot_become_a_command_is_refused_not_skipped():
    """Skipping it would register a plan that is missing a command the runner will
    send - refused at the first preflight, or worse, after the apply."""
    plan = _plan()
    plan["preflight"].append(_check("pf_bad", {"kind": "systemd"}))  # no `unit`
    with pytest.raises(approval.ApprovalError, match="pf_bad"):
        approval.flatten(plan, "rhel")


# ---------------------------------------------------------------------------
# The request the operator signs
# ---------------------------------------------------------------------------
def test_the_request_round_trips_through_the_operators_tool(loopback):
    """The two ends agree on the format, the digest and the nonce. If they drifted
    the operator would be given a token the executor never accepts, with no way to tell
    which end was wrong."""
    plan = _plan()
    request = run(approval.challenge(plan, plan_hash(plan), "rhel"))
    assert request.startswith(approval.REQUEST_PREFIX) == request.startswith(tool.REQUEST_PREFIX)
    parsed = tool.parse_request(request)
    assert parsed["plan_hash"] == plan_hash(plan)
    assert parsed["steps"] == approval.flatten(plan, "rhel").steps
    assert parsed["digest"] == policy.steps_digest(parsed["steps"])


def test_the_request_survives_the_chat_it_travels_through(loopback):
    """Telegram wraps and the operator's terminal pastes: whitespace and line breaks
    inside the request must not change what is signed."""
    plan = _plan()
    request = run(approval.challenge(plan, plan_hash(plan), "rhel"))
    wrapped = "\n".join(request[i:i + 60] for i in range(0, len(request), 60))
    assert tool.parse_request(wrapped) == tool.parse_request(request)


def test_the_request_uses_only_characters_a_chat_client_leaves_alone(loopback):
    """One token, no spaces, and only the url-safe base64 alphabet: no `+`, `/` or `=`
    padding, which messaging clients and terminals treat as word breaks, links or markup.
    A request that arrives altered is refused by the tool with a message about its
    digest or its encoding - the operator would have no way to tell the client did it."""
    import re

    plan = _plan()
    request = run(approval.challenge(plan, plan_hash(plan), "rhel"))
    assert re.fullmatch(r"SENTINEL-APPROVAL-V1:[A-Za-z0-9_-]+", request), request


def test_the_request_alphabet_is_proved_on_a_payload_that_would_use_the_other_one():
    """The test above is only as good as its payload: for `_plan()` the standard base64
    alphabet happens to produce no `+` and no `/`, so switching `build_request` to
    `b64encode` left it green. This one pins a payload that is KNOWN to need both - the
    control is computed here, with the standard alphabet, before anything is asserted - and
    holds the request to the url-safe one: no `+`, no `/`, no `=` padding."""
    import re

    steps = [["systemctl", "restart", "a>>>>>>.service"], ["systemctl", "restart", "b??????.service"]]
    request = approval.build_request("a" * 64, "b" * 64, "c" * 32, steps)

    payload = {"plan_hash": "a" * 64, "digest": "b" * 64, "nonce": "c" * 32, "steps": steps}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True).encode("ascii")
    standard = base64.b64encode(raw).decode("ascii")
    assert "+" in standard and "/" in standard and standard.endswith("="), (
        "control: with the STANDARD alphabet this payload contains `+`, `/` and padding, so "
        "each assertion below can fail")
    assert re.fullmatch(r"SENTINEL-APPROVAL-V1:[A-Za-z0-9_-]+", request), request
    assert "=" not in request, "padding is a word break to a chat client"
    body = request[len(approval.REQUEST_PREFIX):]
    assert base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)) == raw, "and it still decodes to the same bytes"


def test_the_tool_refuses_a_request_whose_digest_is_not_the_digest_of_its_steps(loopback):
    """The bot is the thing that might lie. A request that declares one digest and
    carries other commands is refused by the tool, which recomputes it."""
    plan = _plan()
    request = run(approval.challenge(plan, plan_hash(plan), "rhel"))
    body = request[len(approval.REQUEST_PREFIX):]
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["steps"][2] = ["dnf", "-y", "remove", "openssh-server"]
    forged = approval.REQUEST_PREFIX + base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    with pytest.raises(ValueError, match="NU corespunde"):
        tool.make_token(policy, KEY, tool.parse_request(forged))


def test_challenge_refuses_when_no_key_is_enrolled_and_says_the_executors_reason(monkeypatch, tmp_path):
    """The operator learns at the first tap that nothing can be approved on this host,
    in the executor's own words, not after reading commands and running a tool."""
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", tmp_path / "absent.key")
    client = _Loopback()
    monkeypatch.setattr(approval, "_client", client)
    plan = _plan()
    with pytest.raises(approval.ApprovalError, match="no approval key is enrolled"):
        run(approval.challenge(plan, plan_hash(plan), "rhel"))


def test_a_plan_whose_declared_timeouts_do_not_fit_the_approval_window_is_refused_up_front(loopback):
    """A registration that expires halfway through an apply leaves a half-changed
    machine whose rollback the executor then refuses. The window is checked BEFORE
    the operator is asked to sign."""
    plan = _plan()
    plan["apply"][0]["timeout_s"] = 3000
    with pytest.raises(approval.ApprovalError, match="fereastra de aprobare"):
        run(approval.challenge(plan, plan_hash(plan), "rhel"))
    assert not [c for c in loopback.calls if c["op"] == "plan_challenge"], "the executor was not even asked"


def test_challenge_refuses_an_executor_that_describes_other_commands_than_were_sent(loopback, monkeypatch):
    """A confused or tampered executor answering with a different digest must not get
    the operator's signature on what the bot believes it asked for."""
    real = loopback.call

    def lying(op, **args):
        result = real(op, **args)
        if op == "plan_challenge":
            result = {**result, "digest": "0" * 64}
        return result

    monkeypatch.setattr(loopback, "call", lying)
    plan = _plan()
    with pytest.raises(approval.ApprovalError, match="alte comenzi"):
        run(approval.challenge(plan, plan_hash(plan), "rhel"))


def test_register_returns_the_executors_refusal_as_the_operators_reason(loopback):
    plan = _plan()
    run(approval.challenge(plan, plan_hash(plan), "rhel"))
    with pytest.raises(approval.ApprovalError, match="does not match"):
        run(approval.register(plan, plan_hash(plan), "rhel", "0" * 64))


@pytest.mark.parametrize("answer", [
    {"registered": False, "step_count": 6},
    {"registered": True, "step_count": 5},
    {"step_count": 6},
])
def test_a_registration_the_executor_does_not_confirm_is_not_taken_for_one(loopback, monkeypatch, answer):
    """The operator is told the plan is approved only when the executor says it registered
    ALL of its commands. A short or missing confirmation is a plan that would be refused
    halfway through, with the machine half-changed."""
    plan = _plan()
    request = run(approval.challenge(plan, plan_hash(plan), "rhel"))
    token, _ = tool.make_token(policy, KEY, tool.parse_request(request))
    monkeypatch.setattr(loopback, "call", lambda op, **args: dict(answer))
    with pytest.raises(approval.ApprovalError, match="n-a confirmat"):
        run(approval.register(plan, plan_hash(plan), "rhel", token))


def test_a_request_too_long_for_one_message_is_refused_and_says_why(loopback):
    """A truncated request does not verify, and the operator has no way to tell why: it is
    refused up front, with the size, instead of being cut."""
    plan = _plan()
    plan["post_verification"] = [
        _check(f"pv{n}", {"kind": "command", "argv": ["rpm", "-q", f"a-package-with-a-long-name-{n:03d}"],
                          "expect_exit": [0], "timeout_s": 1}) for n in range(80)]
    with pytest.raises(approval.ApprovalError, match="nu \u00eencape \u00eentr-un mesaj"):
        run(approval.challenge(plan, plan_hash(plan), "rhel"))


# ---------------------------------------------------------------------------
# The runner names the step it replays, on every real call
# ---------------------------------------------------------------------------
def _real_patch_step_calls(client: _Loopback) -> list[dict[str, Any]]:
    return [c for c in client.calls if c["op"] == "patch_step_exec" and not c.get("dry_run")]


def test_a_signed_plan_applies_and_every_real_call_carried_its_registered_index(loopback):
    """The point of the whole mechanism, end to end on the real executor code: sign,
    apply, and every command the runner sent was refused by nothing - because each
    named the step it replays and the executor found exactly that argv there."""
    plan = _plan()
    db = _FakeDB(plan)
    steps = _approve_through_the_tool(plan, plan_hash(plan))
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "succeeded", res.error
    real = _real_patch_step_calls(loopback)
    assert real, "the plan must have run something for this to prove anything"
    for call in real:
        assert call["plan_hash"] == plan_hash(plan)
        assert steps[call["step_index"]] == call["argv"], (
            "the index the runner sent names a DIFFERENT command than the one it ran")
    assert loopback.transactions == [["dnf", "-y", "update", "nginx"]]
    assert "applied" in db.plan_statuses


def test_without_an_approval_nothing_runs_and_the_machine_is_untouched(loopback):
    """No token, no commands: the first real call (a preflight check) is refused by
    the executor, the run stops there and nothing was applied."""
    plan = _plan()
    db = _FakeDB(plan)
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "aborted"
    assert loopback.transactions == [] and loopback.ran == []
    # A check swallows the refusal into its detail; the operator reads the executor's
    # own reason there.
    assert any("no plan is registered" in s.stdout + s.stderr for s in res.steps if not s.ok)


def test_an_approval_for_another_plan_does_not_let_this_one_run(loopback):
    """The binding in practice: a token for plan A is no licence for plan B's commands,
    even when both are fully valid plans."""
    plan_a = _plan()
    plan_b = _plan()
    plan_b["apply"][0]["argv"] = ["dnf", "-y", "update", "httpd"]
    plan_b["target"]["asset_name"] = "httpd"
    _approve_through_the_tool(plan_a, plan_hash(plan_a))
    db = _FakeDB(plan_b)
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "aborted"
    assert loopback.transactions == []


def test_a_dry_run_sends_no_binding_and_needs_no_approval(loopback):
    plan = _plan()
    db = _FakeDB(plan, status="validated")
    res = run(runner.run_plan(db, None, 1, mode="dry_run"))
    assert res.status == "succeeded"
    for call in loopback.calls:
        if call["op"] == "patch_step_exec":
            assert call.get("dry_run") is True
            assert "plan_hash" not in call and "step_index" not in call


def test_the_rollback_steps_are_bound_too(loopback):
    """A rollback the executor refuses for want of the binding is the worst way to find
    out. When the apply fails, the rollback's `dnf downgrade` goes out with ITS index
    and runs."""
    plan = _plan()
    db = _FakeDB(plan)
    steps = _approve_through_the_tool(plan, plan_hash(plan))
    # The post-verification `command` check (`systemctl is-active`) exits non-zero after
    # the update; the health check reads stdout and passes, so it is that one that rolls back.
    loopback.fail = {"systemctl"}
    res = run(runner.run_plan(db, None, 1, mode="apply"))
    assert res.status == "rolled_back", (res.status, res.error)
    assert loopback.transactions == [["dnf", "-y", "update", "nginx"],
                                     ["dnf", "-y", "downgrade", "nginx-1.20.1-14.el9"]]
    rollback_index = approval.flatten(plan, "rhel").ref("rollback", 0)
    assert steps[rollback_index] == ["dnf", "-y", "downgrade", "nginx-1.20.1-14.el9"]


def test_a_plan_whose_commands_cannot_be_listed_is_refused_before_anything_runs(loopback, monkeypatch):
    def boom(*a, **kw):
        raise approval.ApprovalError("nu se poate")

    monkeypatch.setattr(approval, "flatten", boom)
    db = _FakeDB(_plan())
    with pytest.raises(runner.PatchRefused, match="nu poate fi legat"):
        run(runner.run_plan(db, None, 1, mode="apply"))
    assert db.executions == [] and loopback.calls == []


# ---------------------------------------------------------------------------
# A dry run says what the real run would be refused for
# ---------------------------------------------------------------------------
class _RefusingTransaction(_FakeExec):
    """An executor whose gate is closed: its dry run of a package transaction says so."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__()
        self.reasons = reasons

    def call(self, op, **args):
        if op == "patch_step_exec" and args.get("dry_run") and (args.get("argv") or [""])[0] == "dnf":
            self.calls.append({"op": op, **args})
            return {"dry_run": True, "would_run": args["argv"],
                    "transaction": {"transient_unit": True, "refused_because": self.reasons}}
        return super().call(op, **args)


def _wire(monkeypatch, fake):
    for module in (runner, backup_mod, checks_mod):
        monkeypatch.setattr(module, "_client", fake)


def test_a_dry_run_that_the_gate_would_refuse_is_a_failed_dry_run(monkeypatch):
    """The executor's dry run of a package transaction says what the real run would be
    refused for. Ignoring that - reporting every dry run as fine because nothing ran -
    is a green light for an apply that is then refused: unknown reads as fine."""
    fake = _RefusingTransaction(["no approval can be verified on this host: no key"])
    _wire(monkeypatch, fake)
    db = _FakeDB(_plan(), status="validated")
    res = run(runner.run_plan(db, None, 1, mode="dry_run"))
    assert res.status == "aborted"
    failed = [s for s in res.steps if not s.ok]
    assert failed and "no approval can be verified" in failed[0].stderr


def test_an_apply_is_stopped_by_its_own_dry_run_before_anything_is_touched(monkeypatch):
    """Guard 4 already ran a full dry-run pass before an apply; it now actually
    carries the executor's refusal, so the apply stops with the reason BEFORE an
    execution row for it is opened."""
    fake = _RefusingTransaction(["the requester can write /var/lib"])
    _wire(monkeypatch, fake)
    db = _FakeDB(_plan())
    with pytest.raises(runner.PatchRefused, match="proba uscată"):
        run(runner.run_plan(db, None, 1, mode="apply"))
    assert not [c for c in fake.calls if c["op"] == "patch_step_exec" and not c.get("dry_run")]


def test_a_dry_run_with_nothing_to_refuse_is_still_a_success(monkeypatch):
    """The control: an empty `refused_because` is the gate saying yes."""
    fake = _RefusingTransaction([])
    _wire(monkeypatch, fake)
    res = run(runner.run_plan(_FakeDB(_plan(), status="validated"), None, 1, mode="dry_run"))
    assert res.status == "succeeded"


def test_the_dry_run_shown_in_telegram_says_why_a_step_failed(monkeypatch):
    """A dry run that only says a step failed leaves the operator to guess what to fix.
    The executor's reason (no key enrolled, the key readable, the audit directory
    writable) is in the step's stderr; the Telegram message must carry it."""
    from sentinel.telegram import patch_flow

    result = runner.RunResult("aborted", 3, [
        runner.StepOutcome(True, "preflight", "pf1", exit_code=0),
        runner.StepOutcome(False, "apply", "ap1", exit_code=1,
                           stderr="executorul ar refuza acest pas: no approval can be verified on this host"),
    ])

    async def fake_run_plan(*a, **kw):
        return result

    monkeypatch.setattr(runner, "run_plan", fake_run_plan)
    edits: list[str] = []

    class _Progress:
        async def edit_text(self, text, **kw):
            edits.append(text)

    class _Message:
        async def reply_text(self, text, **kw):
            return _Progress()

    update = SimpleNamespace(callback_query=SimpleNamespace(message=_Message()),
                             effective_chat=SimpleNamespace(id=5))
    context = SimpleNamespace(bot_data={"db": object(), "cfg": _cfg()})
    run(patch_flow.on_dry_run(update, context, 1))
    assert "apply/ap1" in edits[-1]
    assert "no approval can be verified on this host" in edits[-1]


# ---------------------------------------------------------------------------
# The Telegram flow: two taps are not an approval
# ---------------------------------------------------------------------------
def _flow_fakes():
    from tests.security.test_patch_pin import _FakeUpdate

    return _FakeUpdate


@pytest.fixture
def flow(loopback, monkeypatch):
    """The real `_ask_for_approval` / `on_approval_reply` / `_approve_and_run`, a
    plan in a fake database and the real executor operations behind the client."""
    from sentinel.telegram import patch_flow

    plan = _plan()
    db = _FakeDB(plan, status="validated")
    patch_flow._pending_approvals.clear()
    patch_flow._pending_pins.clear()
    state = SimpleNamespace(approved=[], db=db, plan=plan, plan_hash=plan_hash(plan))

    async def approve_plan(db_, plan_id, *, by, expected_hash):
        state.approved.append((plan_id, expected_hash))
        db_.status = "approved"
        return True

    async def revoke(*a, **kw):
        return 0

    monkeypatch.setattr(patch_flow.patches, "approve_plan", approve_plan)
    monkeypatch.setattr(patch_flow.approvals, "revoke_for_plan", revoke)
    yield state
    patch_flow._pending_approvals.clear()


def _cfg():
    return SimpleNamespace(platform=SimpleNamespace(family="rhel"),
                           telegram=SimpleNamespace(require_pin_for_apply=False))


class _Prompt:
    message_id = 777


def _ask(flow_state, chat_id=5):
    from sentinel.telegram import patch_flow

    sent: list[str] = []

    async def edit(text, **kw):
        sent.append(text)
        return _Prompt()

    run(patch_flow._ask_for_approval(flow_state.db, _cfg(), edit, chat_id=chat_id, plan_id=1,
                                     plan_hash=flow_state.plan_hash, by=f"telegram:{chat_id}"))
    return sent


def _reply(flow_state, text, chat_id=5, reply_to=777):
    from sentinel.telegram import patch_flow
    from tests.security.test_patch_pin import _FakeUpdate

    update = _FakeUpdate(chat_id=chat_id, text=text, reply_to_message_id=reply_to)
    context = SimpleNamespace(bot_data={"db": flow_state.db, "cfg": _cfg()})
    handled = run(patch_flow.on_approval_reply(update, context))
    return handled, update


def _request_from(sent: list[str]) -> str:
    import re

    match = re.search(r"<code>(SENTINEL-APPROVAL-V1:[^<]+)</code>", sent[-1])
    assert match, sent[-1]
    return match.group(1)


def test_the_two_taps_alone_neither_approve_nor_run(flow, loopback):
    """After the second tap the bot asks for a signature and stops: the plan is still
    `validated`, nothing was approved in the database and the executor ran nothing.
    This is the line a compromised bot would otherwise cross for itself."""
    sent = _ask(flow)
    assert "scripts/approve-plan.py" in sent[-1]
    assert flow.db.status == "validated" and flow.approved == []
    assert loopback.ran == [] and loopback.transactions == []


def test_a_token_signed_on_the_operators_machine_approves_and_runs_the_plan(flow, loopback):
    """The whole flow on real code: ask, the operator's tool signs what it printed, the
    token comes back as a reply, the executor accepts it, the plan is approved in the
    database and applied - and `dnf` really was handed to the transaction path."""
    from sentinel.telegram import patch_flow

    sent = _ask(flow)
    token, _ = tool.make_token(policy, KEY, tool.parse_request(_request_from(sent)))
    handled, update = _reply(flow, token)
    assert handled is True
    assert flow.approved == [(1, flow.plan_hash)]
    assert loopback.transactions[:1] == [["dnf", "-y", "update", "nginx"]]
    assert 5 not in patch_flow._pending_approvals
    assert "succeeded" in update.message.replies[0].edits[-1], update.message.replies[0].edits


def test_a_token_for_other_commands_is_refused_and_nothing_runs(flow, loopback):
    """A token the operator signed for a different plan - or one a compromised bot
    obtained by showing the operator something else - does not approve this one."""
    from sentinel.telegram import patch_flow

    sent = _ask(flow)
    other = [["dnf", "-y", "remove", "openssh-server"]]
    token = sign(flow.plan_hash, other, tool.parse_request(_request_from(sent))["nonce"])
    handled, _update = _reply(flow, token)
    assert handled is True
    assert flow.approved == [] and loopback.transactions == [] and loopback.ran == []
    assert patch_flow._pending_approvals[5].attempts == 1


def test_a_wrong_token_can_be_retried_and_the_right_one_still_works(flow, loopback):
    sent = _ask(flow)
    handled, _ = _reply(flow, "0" * 64)
    assert handled is True and flow.approved == []
    token, _ = tool.make_token(policy, KEY, tool.parse_request(_request_from(sent)))
    _reply(flow, token)
    assert flow.approved == [(1, flow.plan_hash)]


def test_attempts_are_capped_and_the_wait_ends(flow, loopback):
    from sentinel.telegram import patch_flow

    _ask(flow)
    for _ in range(patch_flow.APPROVAL_MAX_ATTEMPTS):
        _reply(flow, "not a token")
    assert 5 not in patch_flow._pending_approvals
    handled, _ = _reply(flow, "0" * 64)
    assert handled is False


def test_a_reply_to_some_other_message_is_not_taken_for_a_token(flow, loopback):
    """Without pinning the reply to the prompt, ordinary conversation in the chat would
    be swallowed as wrong attempts and burn the cap."""
    from sentinel.telegram import patch_flow

    _ask(flow)
    handled, _ = _reply(flow, "0" * 64, reply_to=778)
    assert handled is False
    assert patch_flow._pending_approvals[5].attempts == 0


def test_an_expired_request_is_refused(flow, loopback):
    from sentinel.telegram import patch_flow

    _ask(flow)
    patch_flow._pending_approvals[5].expires_at = time.monotonic() - 1
    handled, _ = _reply(flow, "0" * 64)
    assert handled is True and 5 not in patch_flow._pending_approvals
    assert flow.approved == []


def test_a_plan_that_changed_after_the_request_is_not_approved(flow, loopback):
    """The bytes the operator signed for must be the bytes the taps named: if the stored
    plan changed in between, the token - even a correct one - is not used."""
    sent = _ask(flow)
    token, _ = tool.make_token(policy, KEY, tool.parse_request(_request_from(sent)))
    flow.db.stored_hash = "f" * 64
    handled, _ = _reply(flow, token)
    assert handled is True
    assert flow.approved == [] and loopback.transactions == []


def test_a_token_is_spent_by_its_first_use(flow, loopback):
    """Replaying the token message - a forwarded chat, a second client - approves
    nothing a second time."""
    from sentinel.telegram import patch_flow

    sent = _ask(flow)
    token, _ = tool.make_token(policy, KEY, tool.parse_request(_request_from(sent)))
    _reply(flow, token)
    flow.approved.clear()
    flow.db.status = "validated"
    patch_flow._pending_approvals[5] = patch_flow._PendingApproval(
        plan_id=1, plan_hash=flow.plan_hash, by="telegram:5", expires_at=time.monotonic() + 600,
        prompt_message_id=777)
    _reply(flow, token)
    assert flow.approved == [], "the same token approved a second time"


def test_asking_for_approval_on_a_host_without_a_key_says_so_and_asks_nothing(flow, loopback, monkeypatch, tmp_path):
    from sentinel.telegram import patch_flow

    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", tmp_path / "absent.key")
    sent = _ask(flow)
    assert "no approval key is enrolled" in sent[-1]
    assert 5 not in patch_flow._pending_approvals


def test_the_token_never_reaches_a_log_line(flow, loopback, caplog):
    """Spent after one use, but a log line that carried it would still be a record of
    what the operator's key signed."""
    import logging

    sent = _ask(flow)
    token, _ = tool.make_token(policy, KEY, tool.parse_request(_request_from(sent)))
    with caplog.at_level(logging.DEBUG):
        _reply(flow, token)
    assert token not in caplog.text
