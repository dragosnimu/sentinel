"""A plan step that has nowhere to run is refused before anything is spent, and an
approved step runs once.

The executor runs a plan step in one of two places: a package transaction in a
transient unit with a writable root, everything else inside its own sandbox, where
`/`, `/etc`, `/var` and `/usr` are read-only. A step that WRITES and is not a
transaction therefore fails with "Read-only file system" - measured against the real
executor in a container on 5 October 2026 (see policy.py, "Where a plan step can
run"). Before this existed the dry run answered "would run", the real run failed, and
the runner rolled back a machine nothing had touched and then reported the rollback as
failed: "restore by hand" for a server that was fine.

These tests pin the four places the refusal has to hold - the policy function itself,
the challenge (before the operator signs), the dry run, and the real call - and the
second half of the same change: the sandbox path now SPENDS the approval, so an
approved `systemctl restart` cannot be replayed for the rest of the hour.
"""

from __future__ import annotations

import hashlib
import itertools
import time

import pytest

import commands
import policy
from _approval_support import approve, enrol_key
from policy import PolicyRefusal

pytestmark = pytest.mark.security

_PLAN_HASH = hashlib.sha256(b"sandbox plan").hexdigest()

#: Grammar-LEGAL, write the filesystem, are not package transactions. Each one is a
#: shape a plan really contained or could: the first is n8n plan 1's apply step.
WRITERS = [
    ["tar", "-czf", "/var/backups/polkit-1.tar.gz", "-C", "/", "etc/polkit-1"],
    ["tar", "-xzf", "/var/tmp/x.tgz", "-C", "/"],
    ["tar", "-cf", "/tmp/x.tar", "-C", "/", "var/www/html"],
    ["mkdir", "/var/lib/e2e-probe-dir"],
    ["mkdir", "-p", "/tmp/zz"],
    ["cp", "/etc/hostname", "/etc/hostname.bak"],
    ["mv", "/etc/hostname", "/etc/hostname2"],
    ["install", "-d", "/var/x"],
    ["chmod", "644", "/etc/hostname"],
    ["chown", "root:root", "/etc/hostname"],
    ["nginx", "-t"],
    ["dnf", "check-update"],
    ["dnf", "clean", "all"],
    ["dnf", "makecache"],
    ["apt-get", "update"],
    ["apt", "update"],
]
#: Grammar-legal, and they either read or ask PID 1 - the sandbox measured to run them.
RUNNABLE = [
    ["rpm", "-q", "bash"],
    ["rpm", "-qa"],
    ["dpkg-query", "-W", "bash"],
    ["dpkg", "--compare-versions", "1.0", "lt", "2.0"],
    ["systemctl", "is-active", "nginx.service"],
    ["systemctl", "restart", "nginx.service"],
    ["test", "-e", "/etc/hostname"],
    ["sha256sum", "/etc/hostname"],
    ["tar", "-tzf", "/var/tmp/x.tgz"],
    ["tar", "--zstd", "-tf", "/var/tmp/x.tar.zst", "-C", "/"],
    # transactions: they go to the unit, which can write
    ["dnf", "-y", "update", "nginx"],
    ["apt-get", "-y", "install", "nginx=1.24.0-1"],
]

for _argv in (*WRITERS, *RUNNABLE):
    assert policy.check_argv(_argv) == _argv, f"the grammar must accept {_argv}, or every refusal below is the grammar's"


@pytest.fixture(autouse=True)
def _clean_state():
    policy._plan_registry.clear()
    policy._challenges.clear()
    yield
    policy._plan_registry.clear()
    policy._challenges.clear()


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    return enrol_key(tmp_path, monkeypatch)


@pytest.fixture
def sandbox(monkeypatch):
    """The executor's sandbox, as a recorder: what would have been run in it."""
    ran: list[list[str]] = []

    def fake_run(argv, timeout=30, cwd=None):
        ran.append(list(argv))
        return {"exit_code": 0, "stdout": "", "stderr": "", "duration_ms": 1, "timed_out": False}

    monkeypatch.setattr(commands, "_run", fake_run)
    return ran


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("argv", WRITERS, ids=lambda a: " ".join(a)[:48])
def test_a_step_that_writes_and_is_not_a_transaction_has_a_reason_it_cannot_run(argv):
    """Without a reason the dry run says "would run" and the real run dies with "Read-only
    file system" - after the plan was approved, with the operator watching a rollback of a
    machine nothing changed. The reason names the command and what happens to it."""
    why = policy.sandbox_refusal(argv)
    assert why, f"{argv} has a reason to be refused, and none was given"
    assert f"`{argv[0]}" in why, why
    assert "read-only" in why.lower(), why


@pytest.mark.parametrize("argv", RUNNABLE, ids=lambda a: " ".join(a)[:48])
def test_a_step_that_reads_or_asks_pid_1_or_is_a_transaction_is_not_refused(argv):
    """The control for the test above: a refusal that fired for everything would pass it.
    These ran in the container (or, for the transactions, go to the unit that can write)."""
    assert policy.sandbox_refusal(argv) is None


@pytest.mark.parametrize("argv", [None, [], "mkdir /x", [1, 2]])
def test_a_malformed_argv_is_not_this_functions_to_judge(argv):
    """`check_argv` refuses those; this function is asked only afterwards, and must not
    raise on what it is not meant to see - and must not call "no program" a refusal."""
    assert policy.sandbox_refusal(argv) is None


def test_every_argv_the_package_grammars_accept_is_either_a_transaction_or_a_cache_operation():
    """Exhaustively, over a pool of tokens the grammars treat differently, every argv the
    dnf/apt grammar ACCEPTS has a subcommand the router can read and put on exactly one
    side. The first version read the VALUE of `-o Dpkg::Options::=--force-confold` as the
    subcommand: a real `apt-get -o ... install` was then "not a transaction" and went to
    the read-only sandbox - on the one host that has no other package manager."""
    pool = ["-y", "-o", "Dpkg::Options::=--force-confold", "--allow-downgrades", "install", "update",
            "remove", "clean", "x=1.0", "x", "--enablerepo=crb", "makecache"]
    checked = 0
    for manager in ("dnf", "apt-get", "apt"):
        for length in range(1, 5):
            for tail in itertools.product(pool, repeat=length):
                argv = [manager, *tail]
                try:
                    policy.check_argv(argv)
                except PolicyRefusal:
                    continue
                checked += 1
                sub = policy.package_subcommand(argv)
                routed = sub in policy.TRANSACTION_SUBCOMMANDS[manager]
                cache = sub in policy.CACHE_SUBCOMMANDS[manager]
                assert routed != cache, (argv, sub)
                assert policy.is_package_transaction(argv) is routed
                assert (policy.sandbox_refusal(argv) is None) is routed, argv
    assert checked > 200, f"only {checked} argvs were accepted by the grammar: the pool no longer exercises it"


# ---------------------------------------------------------------------------
# Where the refusal holds
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("argv", WRITERS, ids=lambda a: " ".join(a)[:48])
def test_the_operator_is_never_asked_to_sign_for_a_step_that_cannot_run(enrolled, argv):
    """The challenge is where the operator has spent nothing yet. A plan with a step that
    can only fail must die here - naming WHICH step - not at the first command after the
    PIN and the signature."""
    steps = [["rpm", "-q", "bash"], argv]
    with pytest.raises(PolicyRefusal, match=r"steps\[1\].*cannot run on this host"):
        policy.challenge_plan_steps(_PLAN_HASH, steps)
    assert _PLAN_HASH not in policy._challenges, "a refused challenge must not leave a nonce behind"


def test_a_registration_cannot_slip_such_a_step_past_the_challenge(enrolled):
    """`register_plan` re-validates every step ("registering a plan is never a way around
    the grammar"): it must apply this rule too, or a caller could skip the challenge's
    refusal by registering without it."""
    ok_steps = [["rpm", "-q", "bash"]]
    challenge = policy.challenge_plan_steps(_PLAN_HASH, ok_steps)
    from _approval_support import sign
    bad_steps = [["mkdir", "/var/lib/x"]]
    with pytest.raises(PolicyRefusal, match="cannot run on this host"):
        policy.register_plan_steps(_PLAN_HASH, bad_steps, 600, sign(_PLAN_HASH, bad_steps, challenge["nonce"]))
    assert _PLAN_HASH not in policy._plan_registry


@pytest.mark.parametrize("argv", WRITERS, ids=lambda a: " ".join(a)[:48])
def test_a_dry_run_says_the_step_would_be_refused_not_that_it_would_run(sandbox, argv):
    """The dry run is what the operator and the apply's own pre-pass read. "would run" for
    a step the real run cannot run is the green light that ends in a rollback."""
    report = commands.op_patch_step_exec({"argv": argv, "dry_run": True})
    assert report["dry_run"] is True
    assert report["refused_because"] and isinstance(report["refused_because"][0], str)
    assert sandbox == [], "a dry run ran something"


@pytest.mark.parametrize("argv", [a for a in RUNNABLE if not a[0] in ("dnf", "apt-get")],
                         ids=lambda a: " ".join(a)[:48])
def test_a_dry_run_of_a_step_that_can_run_has_nothing_to_refuse(sandbox, argv):
    assert "refused_because" not in commands.op_patch_step_exec({"argv": argv, "dry_run": True})


@pytest.mark.parametrize("argv", WRITERS, ids=lambda a: " ".join(a)[:48])
def test_a_real_call_is_refused_before_it_runs(sandbox, argv):
    """The last line: even a caller that skips validation, the challenge and the dry run
    gets a refusal and not an exit code 1 (or, under /tmp, an exit 0 for a change that
    exists only inside the executor). Nothing can be registered for such a step (the
    challenge refuses it), so there is no approval here for a refusal to spend."""
    with pytest.raises(PolicyRefusal, match="cannot run on this host"):
        commands.op_patch_step_exec({"argv": argv, "plan_hash": _PLAN_HASH, "step_index": 0})
    assert sandbox == []


# ---------------------------------------------------------------------------
# An approved step runs ONCE
# ---------------------------------------------------------------------------
def test_an_approved_step_that_runs_in_the_sandbox_cannot_be_replayed(enrolled, sandbox):
    """Reproduced against the real executor on 5 October 2026: `systemctl restart
    systemd-logind.service` registered once with a one-hour TTL ran on attempts 0, 1 and
    2. The sandbox path only LOOKED the step up; only transactions spent it. "Approved
    once" meant "runnable at will for the next hour" to anything that could reach the
    socket."""
    steps = [["systemctl", "restart", "nginx.service"], ["systemctl", "is-active", "nginx.service"]]
    approve(_PLAN_HASH, steps, ttl=3600)

    commands.op_patch_step_exec({"argv": steps[0], "plan_hash": _PLAN_HASH, "step_index": 0})
    with pytest.raises(PolicyRefusal, match="already been executed"):
        commands.op_patch_step_exec({"argv": steps[0], "plan_hash": _PLAN_HASH, "step_index": 0})
    assert sandbox == [steps[0]], "the replay ran"

    commands.op_patch_step_exec({"argv": steps[1], "plan_hash": _PLAN_HASH, "step_index": 1})
    assert sandbox == steps, "spending step 0 must not spend step 1"


def test_a_dry_run_does_not_spend_the_approval_it_previews(enrolled, sandbox):
    """The runner's pre-apply dry run sends no binding and runs first; if it used the
    approval up, the real run that follows would be refused."""
    steps = [["systemctl", "restart", "nginx.service"]]
    approve(_PLAN_HASH, steps)
    commands.op_patch_step_exec({"argv": steps[0], "dry_run": True})
    commands.op_patch_step_exec({"argv": steps[0], "dry_run": True, "plan_hash": _PLAN_HASH, "step_index": 0})
    commands.op_patch_step_exec({"argv": steps[0], "plan_hash": _PLAN_HASH, "step_index": 0})
    assert sandbox == steps


def test_a_re_approval_runs_the_step_again_and_nothing_else_does(enrolled, sandbox):
    """The way to run a step twice is the operator signing again: the registration is
    replaced and its used-marks with it."""
    steps = [["systemctl", "restart", "nginx.service"]]
    approve(_PLAN_HASH, steps)
    commands.op_patch_step_exec({"argv": steps[0], "plan_hash": _PLAN_HASH, "step_index": 0})
    approve(_PLAN_HASH, steps)
    commands.op_patch_step_exec({"argv": steps[0], "plan_hash": _PLAN_HASH, "step_index": 0})
    assert sandbox == steps * 2


def test_a_registration_lives_exactly_as_long_as_the_ttl_it_was_given(enrolled, monkeypatch):
    """The TTL is chosen by the client and is not covered by the token, so the only thing
    that makes it mean anything is that the registry honours it. A registration for 1 s must
    be gone after 2 s; one for 3600 s must not be: with the TTL ignored (or replaced by a
    constant) one of the two assertions fails."""
    short_hash, long_hash = hashlib.sha256(b"short").hexdigest(), hashlib.sha256(b"long").hexdigest()
    step = [["systemctl", "restart", "nginx.service"]]
    approve(short_hash, step, ttl=1)
    approve(long_hash, step, ttl=3600)
    policy.lookup_registered_step(short_hash, 0, step[0])
    policy.lookup_registered_step(long_hash, 0, step[0])

    real = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real() + 2)
    with pytest.raises(PolicyRefusal, match="expired"):
        policy.lookup_registered_step(short_hash, 0, step[0])
    policy.lookup_registered_step(long_hash, 0, step[0])


def test_the_registry_is_not_wider_than_the_largest_ttl_it_accepts():
    """The TTL ceiling is what bounds a registration a client keeps alive: it is the
    documented 3600 s, and `approval.APPROVAL_TTL_S` (what the bot asks for) is not above it."""
    from sentinel.patch import approval

    assert policy._MAX_TTL_S == 3600
    assert approval.APPROVAL_TTL_S <= policy._MAX_TTL_S
