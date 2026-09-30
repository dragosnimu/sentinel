"""The transient-unit path for package transactions (executor/transient_unit.py).

The executor's own sandbox is read-only where a package transaction has to write,
so an approved `dnf` step is handed to systemd to run in a transient unit whose
properties are fixed in code. That unit is, for practical purposes, unconfined
root: everything that stands between a socket peer and that root is in the tests
below, and each test names what goes wrong for the operator if it stops holding.

Every test in the gate section starts from `test_the_gate_is_open_when_every_fact_holds`
- an open gate is the positive control. Without it, "refused" would also be what
a broken fixture produces, and the refusals below would prove nothing.
"""

from __future__ import annotations

import ast
import errno
import hashlib
import hmac
import inspect
import json
import os
import re
import stat as stat_module
import subprocess
import sys
import threading
import time
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "executor"))

import commands  # noqa: E402
import policy  # noqa: E402
import sentinel_executor as se  # noqa: E402
import transient_unit as tu  # noqa: E402
from policy import PolicyRefusal  # noqa: E402

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]
KEY = "unit-test-approval-key-not-a-secret"
PLAN_HASH = hashlib.sha256(b"a plan").hexdigest()
AUDIT = "/var/lib/sentinel-executor/audit.jsonl"
UPDATE = ["dnf", "-y", "update", "nginx"]
ROLLBACK = ["dnf", "-y", "downgrade", "nginx-1.24.0-1.el9"]
KEY_PATH = str(policy.approval_key_path())

# The argvs used as "an approved step" must be legal for the grammar. If they
# were not, every refusal below could be the grammar's and prove nothing.
for _argv in (UPDATE, ROLLBACK):
    assert policy.check_argv(_argv) == _argv


def _token(plan_hash: str = PLAN_HASH) -> str:
    return hmac.new(KEY.encode(), plan_hash.encode(), hashlib.sha256).hexdigest()


# 32 hex digits, built by repetition: a 32-character hex LITERAL in a tracked file is
# what tests/security/test_repo_is_sanitised.py reads as a leaked secret.
INVOCATION = "ab12" * 8
#: What `systemctl show` prints for a unit that does not exist. Note `Result=success`:
#: an absent unit "succeeded", which is exactly why absent must never be an outcome.
ABSENT = {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "Result": "success",
          "ExecMainCode": "0", "ExecMainStatus": "0", "InvocationID": "", "Transient": "no",
          "FragmentPath": "", "ExecMainStartTimestampMonotonic": "0", "ExecMainExitTimestampMonotonic": "0"}


def _unit(active="active", sub="exited", result="success", code="1", status="0",
          invocation=INVOCATION, **extra) -> dict[str, str]:
    """A transient unit as PID 1 reports it."""
    state = {"LoadState": "loaded", "ActiveState": active, "SubState": sub, "Result": result,
             "ExecMainCode": code, "ExecMainStatus": status, "InvocationID": invocation,
             "Transient": "yes", "FragmentPath": "/run/systemd/transient/sentinel-txn.service",
             "ExecMainStartTimestampMonotonic": "1000000", "ExecMainExitTimestampMonotonic": "3500000"}
    state.update(extra)
    return state


def _outcome_ok(**fields) -> dict:
    base = dict(exit_code=0, stdout="Complete!", stderr="[sentinel-txn] result=success", result="success",
                unit_ran=True, verified=True, invocation_id=INVOCATION, outcome="finished", duration_ms=5)
    base.update(fields)
    return tu._outcome(**base)


class Rig:
    """Everything the transaction path touches, replaced by something that records."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.rows: list[tuple[str, str, dict]] = []
        self.spawned: list[list[str]] = []
        self.audit_ok = True
        self.audit_end_ok = True
        #: the control probes must answer yes for the gate to mean anything
        self.probes: dict[tuple[str, str], bool | None] = {
            ("-r", tu.TEST): True, ("-w", tu.WRITE_CONTROL): True}
        self.probe_calls: list[tuple[str, str]] = []
        #: paths whose mount is read-only in the executor's namespace, and what the
        #: mode bits say about each of them
        self.read_only: set[str] = set()
        self.read_only_unknown: set[str] = set()
        self.stat_answers: dict[str, tuple[bool | None, str]] = {}
        self.stat_calls: list[str] = []
        self.outcome = _outcome_ok()
        self.on_execute = None
        #: PID 1's view of the unit, the marker, and what closing the record did
        self.unit: dict[str, str] | None = dict(ABSENT)
        self.marker: dict | None = None
        self.marker_write_ok = True
        self.marker_clear_ok = True
        self.release_ok: bool | None = True
        self.released: list[str | None] = []

    def audit_write(self, event: str, result: str, detail: dict) -> bool:
        self.events.append(f"audit:{event}")
        self.rows.append((event, result, detail))
        return self.audit_end_ok if event == "end" else self.audit_ok

    def probe(self, flag: str, path: str):
        self.probe_calls.append((flag, path))
        return self.probes.get((flag, path), False)

    def mount_read_only(self, path: str):
        if path in self.read_only_unknown:
            return None
        return path in self.read_only

    def stat_says(self, path: str):
        self.stat_calls.append(path)
        return self.stat_answers.get(path, (False, "test default: no write access"))

    def execute(self, command: list[str], timeout_s: int) -> dict:
        self.events.append("spawn")
        self.spawned.append(command)
        if self.on_execute is not None:
            self.on_execute()
        return dict(self.outcome)

    def write_marker(self, record: dict) -> bool:
        self.events.append("marker:write")
        if not self.marker_write_ok:
            return False
        self.marker = dict(record)
        return True

    def read_marker(self):
        return None if self.marker is None else dict(self.marker)

    def clear_marker(self) -> bool:
        self.events.append("marker:clear")
        if not self.marker_clear_ok:
            return False
        self.marker = None
        return True

    def release(self, expected_id):
        self.events.append("release")
        self.released.append(expected_id)
        return self.release_ok


@pytest.fixture
def rig(monkeypatch):
    """A wired, open gate, an approved two-step plan, and nothing real underneath."""
    rig = Rig()
    monkeypatch.setattr(policy, "_load_approval_key", lambda: KEY)
    policy._plan_registry.clear()
    monkeypatch.setattr(tu, "_probe", rig.probe)
    monkeypatch.setattr(tu, "_mount_read_only", rig.mount_read_only)
    monkeypatch.setattr(tu, "_stat_says_requester_can_write", rig.stat_says)
    monkeypatch.setattr(tu, "_execute", rig.execute)
    monkeypatch.setattr(tu, "_unit_state", lambda: rig.unit)
    monkeypatch.setattr(tu, "_write_marker", rig.write_marker)
    monkeypatch.setattr(tu, "_read_marker", rig.read_marker)
    monkeypatch.setattr(tu, "_clear_marker", rig.clear_marker)
    monkeypatch.setattr(tu, "_release_unit", rig.release)
    monkeypatch.setattr(tu, "_audit_write", rig.audit_write)
    monkeypatch.setattr(tu, "_audit_path", PurePosixPath(AUDIT))
    monkeypatch.setattr(tu, "_stop", None)
    monkeypatch.setattr(tu, "_closed_invocations", set())
    policy.register_plan_steps(PLAN_HASH, [UPDATE, ROLLBACK], 600, _token())
    yield rig
    policy._plan_registry.clear()


def _run(argv=None, index=0, timeout=60, **kw):
    return tu.run(list(argv or UPDATE), timeout_s=timeout, plan_hash=PLAN_HASH,
                  step_index=index, **kw)


# ---------------------------------------------------------------------------
# Which commands are transactions
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("subcommand", ["upgrade", "update", "install", "downgrade",
                                        "reinstall", "remove"])
def test_every_mutating_dnf_subcommand_is_routed(subcommand):
    """A package-writing subcommand that is not routed runs in the executor's
    read-only sandbox and fails there with an error about /var/log/dnf.log - the
    failure this whole path exists to end."""
    assert tu.is_transaction(["dnf", "-y", subcommand, "nginx"]) is True


@pytest.mark.parametrize("subcommand", ["clean", "check-update", "makecache"])
def test_the_other_dnf_subcommands_are_not_routed(subcommand):
    """Giving a cache refresh an unconfined unit widens what a request can reach
    for no package change; those stay where they were, until someone decides."""
    assert tu.is_transaction(["dnf", subcommand]) is False


def test_every_grammar_subcommand_is_classified_by_a_human():
    """A subcommand added to the dnf grammar tomorrow must not become, by
    default, either an unconfined-root command or one that silently fails."""
    routed = tu.MUTATING_SUBCOMMANDS["dnf"]
    kept = tu.NOT_ROUTED_SUBCOMMANDS["dnf"]
    assert not routed & kept
    assert routed | kept == set(policy._DNF_SUBCOMMANDS)


@pytest.mark.parametrize("argv", [
    ["rpm", "-q", "nginx"], ["systemctl", "is-active", "nginx.service"],
    ["apt-get", "-y", "install", "nginx"], ["cp", "-v", "/etc/a", "/etc/b"],
    ["/opt/sentinel/bin/dnf", "-y", "update", "x"], ["/usr/bin/dnf", "-y", "update", "x"],
    [], "dnf -y update x", None, [1, 2], ["dnf"], ["dnf", "-y"], ["dnf", 5],
])
def test_only_the_bare_dnf_name_is_ever_routed(argv):
    """Routing decides who gets an unconfined unit. Anything it cannot recognise
    exactly must stay in the sandbox, which is the safe side of every mistake."""
    assert tu.is_transaction(argv) is False


def test_flags_in_front_of_the_subcommand_do_not_hide_it():
    """`--enablerepo=` before `install` used to be enough to look like "no
    subcommand" to a naive `argv[1]` check - a real install running unrouted."""
    assert tu.is_transaction(["dnf", "--enablerepo=crb", "-y", "install", "x"]) is True


def test_a_subcommand_word_used_as_a_package_name_does_not_route():
    """`dnf clean install` is grammar-legal (`install` is a valid package name).
    dnf reads `clean`; routing must read it the same way or a cache clean would
    be handed an unconfined unit."""
    argv = ["dnf", "clean", "install"]
    assert policy.check_argv(argv) == argv
    assert tu.is_transaction(argv) is False


# ---------------------------------------------------------------------------
# The bytes that reach systemd
# ---------------------------------------------------------------------------
HOSTILE_TOKENS = ["foo:${HOME}", "foo:$HOME", "foo:%n", "foo:%%", "foo:a\\b", "foo:a'b",
                  'foo:a"b', "foo:é", "foo:a,b", "foo:a@b", "foo:a*", "foo:a~b"]


@pytest.mark.parametrize("token", HOSTILE_TOKENS)
def test_a_token_systemd_would_rewrite_is_refused_although_the_grammar_allows_it(token):
    """The grammar lets anything but `/` and whitespace follow a `:`. systemd
    substitutes `$VAR` and `%specifier` in an exec line, so `foo:${HOME}` would
    reach dnf as a different string from the one that was validated - the
    "byte-identical" property gone, silently. Both halves are asserted: the
    grammar accepts it (else this proves nothing) and the transaction refuses."""
    argv = ["dnf", "-y", "install", token]
    assert policy.check_argv(argv) == argv
    with pytest.raises(PolicyRefusal, match="letters, digits"):
        tu.check_shape(argv)


@pytest.mark.parametrize("argv", [
    UPDATE, ROLLBACK, ["dnf", "-y", "install", "nginx:1.24"],
    ["dnf", "--enablerepo=crb", "--setopt=install_weak_deps=False", "-y", "install", "gcc-c++"],
])
def test_ordinary_transactions_pass_the_shape_check(argv):
    """The check must not refuse the commands the planner actually emits."""
    tu.check_shape(argv)


def test_an_over_long_token_is_refused():
    """The grammar's limit is 4096 characters a token; the audit row's is not."""
    with pytest.raises(PolicyRefusal):
        tu.check_shape(["dnf", "-y", "install", "a" * (tu._MAX_TOKEN_CHARS + 1)])


def test_a_command_too_long_for_one_audit_row_is_refused_not_truncated():
    """audit() cuts `detail` at 1000 characters. A root command whose record shows
    only its first 900 characters is a record that lies by omission."""
    argv = ["dnf", "-y", "install", *(f"package-number-{n:03d}" for n in range(40))]
    assert policy.check_argv(argv) == argv
    with pytest.raises(PolicyRefusal, match="audit row"):
        tu.check_shape(argv)


def test_the_largest_start_row_still_fits_in_the_audit_detail_field(rig):
    """If the "start" detail passed audit()'s 1000-character cut, the end of the
    argv - the part that names what was removed - would be what vanished."""
    argv = ["dnf", "-y", "install"]
    while True:
        room = tu.MAX_AUDITED_ARGV_CHARS - len(json.dumps(argv + ['""'], separators=(",", ":"))) + 3
        if room <= 0:
            break
        argv.append("a" * min(100, room))
        if len(json.dumps(argv, separators=(",", ":"))) >= tu.MAX_AUDITED_ARGV_CHARS:
            break
    assert tu.MAX_AUDITED_ARGV_CHARS - 5 <= len(json.dumps(argv, separators=(",", ":"))) <= tu.MAX_AUDITED_ARGV_CHARS
    policy.register_plan_steps(PLAN_HASH, [argv], 600, _token())
    _run(argv, index=0)
    detail = rig.rows[0][2]
    assert len(json.dumps(detail, sort_keys=True, separators=(",", ":"))) <= 1000


def _split(command: list[str]) -> tuple[list[str], list[str]]:
    sep = command.index("--")
    return command[:sep], command[sep + 1:]


@pytest.mark.parametrize("argv", [
    UPDATE, ROLLBACK, ["dnf", "install", "-y", "a", "b:c"],
    ["dnf", "--enablerepo=crb", "-y", "install", "x-1.0-1.el9"],
])
def test_what_follows_the_separator_is_the_validated_argv_byte_for_byte(argv):
    """The command systemd runs must be the command the grammar approved: the
    program resolved to an absolute path and every other token untouched. Any
    re-joining, quoting or re-parsing would make the approved argv and the
    executed one two different things."""
    before, after = _split(tu.build_command(argv))
    assert after == [tu.PROGRAMS["dnf"], *argv[1:]]
    assert after[0] == "/usr/bin/dnf"


def test_nothing_before_the_separator_depends_on_the_request():
    """Unit properties, name, working directory and environment are constants.
    If any of them varied with the argv, a request could shape its own unit."""
    a = _split(tu.build_command(UPDATE))[0]
    b = _split(tu.build_command(["dnf", "-y", "install", "zzmarker-package"]))[0]
    assert a == b
    assert not any("zzmarker" in part for part in b)


def test_build_command_takes_the_argv_and_nothing_else():
    """The signature is the argument: there is no parameter through which a
    property, a name, a directory or an environment could be passed."""
    assert list(inspect.signature(tu.build_command).parameters) == ["argv"]


def test_run_accepts_only_the_fields_a_request_may_supply():
    """`run` is the one entry point. A new parameter here is a new way for a
    request to reach the unit and must be a deliberate, reviewed change."""
    assert set(inspect.signature(tu.run).parameters) == {
        "argv", "timeout_s", "plan_hash", "step_index", "redact"}


def test_the_unit_has_no_client_to_die_and_no_collector_to_erase_its_verdict():
    """Measured: with `--pipe` the unit's stdout is the client's pipe, so an executor
    OOM-stop or SIGKILL made the next write fail - `dnf -y install tree` killed at
    0.3 s came out `exit 0` and `rpm -q tree` said not installed. With `--collect` a
    failed unit was garbage-collected and `systemctl show` answered success/0 for it.
    Neither flag may come back; the operator would be told a transaction that did not
    happen had succeeded."""
    before, _ = _split(tu.build_command(UPDATE))
    for flag in ("--no-ask-password", "--service-type=exec", f"--unit={tu.UNIT}", "--working-directory=/"):
        assert flag in before, flag
    for banned in ("--pipe", "-P", "--wait", "-W", "--collect", "--pty", "-t", "--shell", "-S",
                   "--scope", "--user", "--uid", "--same-dir", "-d", "--remain-after-exit", "-r"):
        assert banned not in before, banned
    props = _properties()
    assert props["RemainAfterExit"] == "yes", "without it the verdict is gone the moment the process exits"
    assert props["StandardOutput"] == "journal" and props["StandardError"] == "journal"
    assert not any(part.startswith(("--collect", "--pipe", "--wait")) for part in before)


def _properties() -> dict[str, str]:
    before, _ = _split(tu.build_command(UPDATE))
    props = [p.split("=", 1) for p in (b[len("--property="):] for b in before
                                       if b.startswith("--property="))]
    names = [name for name, _ in props]
    assert len(names) == len(set(names)), "a property set twice is ambiguous"
    return dict(props)


def test_the_root_filesystem_stays_read_only_except_where_packages_go():
    """ProtectSystem=off would make every other line here decoration."""
    props = _properties()
    assert props["ProtectSystem"] == "strict"
    writable = {path.lstrip("-") for path in props["ReadWritePaths"].split()}
    assert {"/usr", "/boot", "/etc", "/var"} <= writable
    assert not writable & {"/", "/home", "/root", "/tmp", "/proc", "/sys"}
    assert props["ProtectHome"] == "yes" and props["PrivateTmp"] == "yes"


def test_a_path_the_host_may_not_have_cannot_kill_the_unit_before_dnf_starts():
    """Seen in a lab on AlmaLinux 9.8: `ReadWritePaths=/boot` on a host with no
    /boot made systemd fail the unit with status 226/NAMESPACE before dnf ran -
    and a failure that looks like a failed transaction sends the plan into
    rollback for something that never started. Every path is written with the
    `-` that makes a missing one harmless."""
    props = _properties()
    for name in ("ReadWritePaths", "InaccessiblePaths"):
        for path in props[name].split():
            assert path.startswith("-"), f"{name}: {path}"


@pytest.mark.parametrize("anchor", [
    "/etc/sentinel", "/var/lib/sentinel", "/var/lib/sentinel-executor",
    "/var/backups/sentinel", "/run/sentinel", "/opt/sentinel"])
def test_sentinels_own_trust_anchors_are_invisible_to_a_transaction(anchor):
    """Secrets, the audit chain, the backups, the executor's code and its socket
    live under directories the transaction is otherwise allowed to write
    (/etc, /var, /opt, /run). A scriptlet that could rewrite the audit chain
    would erase the record of itself."""
    masked = {p.lstrip("-") for p in _properties()["InaccessiblePaths"].split()}
    assert anchor in masked


@pytest.mark.parametrize("prop", ["RestrictSUIDSGID", "ProtectKernelModules", "PrivateDevices"])
def test_the_protections_rpm_cannot_live_with_are_named_off(prop):
    """Each of these looks like hardening and breaks a real transaction half-way:
    RestrictSUIDSGID fails `dnf -y reinstall util-linux-core` (`Error unpacking rpm
    package`, reproduced), ProtectKernelModules hides /usr/lib/modules so no kernel
    installs. A half-applied rpm transaction is worse than none. They are written as
    `no`, not left to a default, so turning one on means deleting the line that says
    why."""
    assert _properties()[prop] == "no"


@pytest.mark.parametrize("prop", ["NoNewPrivileges", "MemoryDenyWriteExecute"])
def test_the_protections_a_real_run_showed_compatible_are_on(prop):
    """Both were once dropped because nobody had tried them; a lab run with both on
    installed, removed, reinstalled a setuid package and upgraded sixteen packages
    (systemd, pam, openssl, coreutils). A protection is dropped only when a run shows
    it necessary. Turned off here, a compromised scriptlet gets one more thing for free."""
    assert _properties()[prop] == "yes"


def test_capabilities_a_package_manager_needs_are_not_taken_away():
    """rpm chowns, sets file capabilities and setuid bits, and scriptlets kill and
    chroot. A deny-list that reached into these would break patching invisibly."""
    denied = set(_properties()["CapabilityBoundingSet"].lstrip("~").split())
    for needed in ("CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
                   "CAP_FSETID", "CAP_SETFCAP", "CAP_SETUID", "CAP_SETGID", "CAP_KILL",
                   "CAP_MKNOD", "CAP_SYS_CHROOT", "CAP_AUDIT_WRITE"):
        assert needed not in denied, needed


def test_capabilities_that_reach_outside_a_package_manager_are_taken_away():
    """CAP_NET_ADMIN is the one that would let a scriptlet edit the Sentinel
    nftables table; CAP_AUDIT_CONTROL would let it switch auditing off; the
    rest load code into the kernel or read raw memory."""
    props = _properties()["CapabilityBoundingSet"]
    assert props.startswith("~"), "an allow-list here would be untestable; a deny-list is meant"
    denied = set(props.lstrip("~").split())
    for gone in ("CAP_NET_ADMIN", "CAP_AUDIT_CONTROL", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
                 "CAP_SYS_BOOT", "CAP_SYS_PTRACE", "CAP_BPF"):
        assert gone in denied, gone


def test_only_the_address_families_dnf_needs():
    """AF_NETLINK is there because glibc's resolver asks the kernel about
    interfaces; nothing else (AF_PACKET, AF_VSOCK, ...) has a use here."""
    assert set(_properties()["RestrictAddressFamilies"].split()) == {
        "AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"}


def test_the_unit_has_a_ceiling_of_its_own_that_outlives_the_executor():
    """A transaction that hangs must not depend on the executor to be stopped: the
    executor may itself have been restarted. And SIGKILL in the middle of an rpm
    transaction is the worst thing that can happen to the package database, so the
    grace between SIGTERM and SIGKILL is generous."""
    props = _properties()
    assert props["RuntimeMaxSec"] == "3600"
    assert int(props["TimeoutStopSec"]) >= 120
    for limit in ("MemoryMax", "TasksMax", "CPUWeight", "IOWeight", "Nice"):
        assert limit in props, limit


def test_the_environment_of_the_unit_is_fixed():
    """A PATH inherited from a request-influenced process is the oldest way to
    make a root process run someone else's binary."""
    assert "PATH=/usr/sbin:/usr/bin" in tu.UNIT_ENVIRONMENT
    assert not any(item.startswith(("LD_", "PYTHON", "SUDO", "SSH")) for item in tu.UNIT_ENVIRONMENT)


def test_the_gate_reads_no_environment_variable_and_no_config():
    """"Not switchable by a flag" has to be true of the source, not of the
    README: any os.environ / getenv read here is a switch someone can flip."""
    tree = ast.parse((REPO / "executor" / "transient_unit.py").read_text(encoding="utf-8"))
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    names |= {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not names & {"environ", "getenv", "getenvb", "ConfigParser", "safe_load", "load"}


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
def test_the_gate_is_open_when_every_fact_holds(rig):
    """The positive control for everything below."""
    assert tu.refusal_reasons() == []
    assert _run()["exit_code"] == 0


def _refused_and_nothing_happened(rig, match):
    with pytest.raises(PolicyRefusal, match=match):
        _run()
    assert rig.spawned == []
    assert rig.rows == []
    assert not tu._transaction_lock.locked()


def test_refused_when_no_audit_sink_is_wired(rig, monkeypatch):
    """A privileged spawn that leaves no trace is worse than no spawn."""
    monkeypatch.setattr(tu, "_audit_write", None)
    _refused_and_nothing_happened(rig, "audit sink")


def test_refused_when_no_audit_path_is_known(rig, monkeypatch):
    """Without the path the tamper check cannot be made, and "cannot check" is
    not "fine"."""
    monkeypatch.setattr(tu, "_audit_path", None)
    _refused_and_nothing_happened(rig, "audit sink")


@pytest.mark.parametrize("answer", [False, None])
def test_refused_when_the_probe_cannot_prove_it_works(rig, answer):
    """If `test -r` on a world-readable file as the requester does not say yes,
    the probe is broken (wrong uid, no exec, no such user) and every "cannot
    read" it would report afterwards is noise. It must not read as "fine"."""
    rig.probes[("-r", tu.TEST)] = answer
    assert len(tu.refusal_reasons()) == 1
    _refused_and_nothing_happened(rig, "cannot check")


@pytest.mark.parametrize("answer", [False, None])
def test_refused_when_the_write_probe_cannot_prove_it_can_say_yes(rig, answer):
    """The read control proves nothing about `-w`: a `-w` that cannot answer yes (the
    write bit is not passed, the uid is wrong, EROFS for everything) reports "not
    writable" for every path in the audit chain, and the gate would open on a probe
    that never worked. `/dev/null` is writable by everyone and exempt from a
    read-only mount, so a False there means the probe, not the host."""
    rig.probes[("-w", tu.WRITE_CONTROL)] = answer
    assert len(tu.refusal_reasons()) == 1
    _refused_and_nothing_happened(rig, "cannot check what the requester may write")
    assert not [call for call in rig.probe_calls if call[0] == "-w" and call[1] != tu.WRITE_CONTROL]


def test_refused_when_the_requester_can_read_the_approval_key(rig):
    """The failure this whole path is gated on: the key an approval is signed with
    is readable by the account the approval is supposed to constrain, so that
    account can approve itself. This is the state of every host today."""
    rig.probes[("-r", KEY_PATH)] = True
    _refused_and_nothing_happened(rig, "approval key .* readable by the requester")


def test_refused_when_it_cannot_be_determined_whether_the_key_is_readable(rig):
    rig.probes[("-r", KEY_PATH)] = None
    _refused_and_nothing_happened(rig, "could not determine whether the requester can read")


def test_the_key_that_is_probed_is_the_one_policy_verifies_against(rig, monkeypatch):
    """Probing a hard-coded path while policy verifies tokens against another
    would be a gate that checks the wrong file and reports it clean."""
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", Path("/etc/somewhere/else.env"))
    tu.refusal_reasons()
    assert ("-r", str(Path("/etc/somewhere/else.env"))) in rig.probe_calls
    assert ("-r", KEY_PATH) not in rig.probe_calls


AUDIT_CHAIN = [AUDIT, "/var/lib/sentinel-executor", "/var/lib", "/var", "/"]


def test_every_ancestor_of_the_audit_file_is_part_of_the_chain():
    """Owning any directory above the audit file lets the requester rename the
    audit directory away and put its own there - the September finding on
    /var/lib/sentinel."""
    assert tu._audit_chain_paths(PurePosixPath(AUDIT)) == AUDIT_CHAIN


@pytest.mark.parametrize("path", AUDIT_CHAIN)
def test_refused_when_the_requester_can_write_any_part_of_the_audit_chain(rig, path):
    """At HEAD the chain lives under a directory `sentinel` owns, so the record of
    what runs as root is something the unprivileged side can replace."""
    rig.probes[("-w", path)] = True
    _refused_and_nothing_happened(rig, "requester can write")


@pytest.mark.parametrize("path", AUDIT_CHAIN)
def test_refused_when_writability_of_the_audit_chain_is_unknown(rig, path):
    rig.probes[("-w", path)] = None
    _refused_and_nothing_happened(rig, "could not determine whether the requester can write")


# ---------------------------------------------------------------------------
# The probe itself
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("returncode,expected", [(0, True), (1, False), (2, None), (126, None),
                                                 (127, None), (-9, None)])
def test_the_probe_reads_only_test_s_own_two_answers(monkeypatch, returncode, expected):
    """`test` answers with 0 or 1. Exit 126/127 is "could not run it as that user";
    reading it as "not readable" would report a broken probe as a clean host."""
    monkeypatch.setattr(tu, "_requester", lambda: (983, 982, [982, 989]))
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert tu._probe("-r", "/etc/x") is expected
    assert seen["argv"] == [tu.TEST, "-r", "/etc/x"]
    kwargs = seen["kwargs"]
    assert (kwargs["user"], kwargs["group"], kwargs["extra_groups"]) == (983, 982, [982, 989])
    assert kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("error", [OSError("no such user"), PermissionError("setuid"),
                                   subprocess.TimeoutExpired("test", 10), ValueError("user"),
                                   TypeError("user")])
def test_the_probe_that_cannot_run_answers_unknown(monkeypatch, error):
    monkeypatch.setattr(tu, "_requester", lambda: (983, 982, [982]))

    def boom(*a, **k):
        raise error

    monkeypatch.setattr(subprocess, "run", boom)
    assert tu._probe("-r", "/etc/x") is None


def test_the_probe_without_a_requester_account_answers_unknown_and_runs_nothing(monkeypatch):
    monkeypatch.setattr(tu, "_requester", lambda: None)

    def boom(*a, **k):
        raise AssertionError("must not run")

    monkeypatch.setattr(subprocess, "run", boom)
    assert tu._probe("-r", "/etc/x") is None


# ---------------------------------------------------------------------------
# run(): what happens, and in what order
# ---------------------------------------------------------------------------
def test_an_approved_step_is_marked_audited_then_spawned_then_closed_in_order(rig):
    """The order is the guarantee. Before the spawn: the pending marker and the row that
    says a root command is about to run are on disk. After it: the end row, THEN the
    marker is removed, THEN the unit is released - so the verdict is still readable in
    PID 1 until the row that describes it exists."""
    result = _run()
    assert rig.events == ["marker:write", "audit:start", "spawn", "audit:end", "marker:clear", "release"]
    assert result["exit_code"] == 0
    assert result["transaction"]["audit_end_recorded"] is True
    assert result["transaction"]["unit_released"] is True
    assert rig.marker is None and rig.released == [INVOCATION]


def test_the_start_row_records_what_was_spawned_and_can_be_matched_to_it(rig):
    """"What was spawned, with what argv" - and a hash of the whole command line,
    so the row and the process cannot be quietly two different things."""
    _run(ROLLBACK, index=1, timeout=90)
    event, result, detail = rig.rows[0]
    assert (event, result) == ("start", "ok")
    assert detail["argv"] == ROLLBACK
    assert (detail["plan_hash"], detail["step_index"], detail["timeout_s"]) == (PLAN_HASH, 1, 90)
    assert detail["unit"] == tu.UNIT_FULL
    assert detail["command_sha256"] == hashlib.sha256(json.dumps(rig.spawned[0]).encode()).hexdigest()


def test_the_end_row_records_what_happened(rig):
    rig.outcome = _outcome_ok(exit_code=1, result="exit-code", verified=True)
    _run()
    event, result, detail = rig.rows[1]
    assert (event, result) == ("end", "error")
    assert detail["exit_code"] == 1 and detail["result"] == "exit-code"
    assert detail["verified"] is True and detail["timed_out"] is False
    assert detail["invocation_id"] == INVOCATION and detail["recovered"] is False
    assert (detail["plan_hash"], detail["step_index"]) == (PLAN_HASH, 0)


def test_the_pending_marker_names_the_plan_step_and_is_there_while_the_unit_runs(rig):
    """The marker is what lets a restarted executor say "a transaction was started and
    never closed" when the unit can no longer answer (a reboot). It must be on disk
    before the spawn and say which approved step it was."""
    seen = {}
    rig.on_execute = lambda: seen.update(marker=dict(rig.marker))
    _run(ROLLBACK, index=1)
    assert seen["marker"]["plan_hash"] == PLAN_HASH and seen["marker"]["step_index"] == 1


def test_when_the_marker_cannot_be_written_nothing_is_spawned(rig):
    """Without the marker a crash leaves a transaction the restarted executor cannot
    know it started, so the spawn does not happen."""
    rig.marker_write_ok = False
    with pytest.raises(PolicyRefusal, match="marker could not be written, so nothing was started"):
        _run()
    assert rig.spawned == [] and rig.rows == []
    assert not tu._transaction_lock.locked()


def test_when_the_start_row_cannot_be_written_the_marker_does_not_outlive_it(rig):
    """A marker with no start row would make the next restart record a transaction that
    never began as "lost"."""
    rig.audit_ok = False
    with pytest.raises(PolicyRefusal, match="could not be written"):
        _run()
    assert rig.marker is None and rig.spawned == []


def test_a_transaction_left_open_is_not_recorded_marked_off_or_released(rig):
    """The executor was told to stop, or lost sight of the unit: the transaction may
    still be running. Writing an end row would invent an outcome, clearing the marker
    would forget it, releasing the unit would destroy the only place its verdict will
    appear. Nothing is done; the next reconcile does it."""
    rig.outcome = _outcome_ok(exit_code=tu.EXIT_UNVERIFIED, outcome="detached", open=True, verified=False)
    result = _run()
    assert rig.events == ["marker:write", "audit:start", "spawn"]
    assert rig.marker is not None and rig.released == []
    assert result["exit_code"] == tu.EXIT_UNVERIFIED
    assert result["transaction"]["still_running_or_unknown"] is True
    assert result["transaction"]["audit_end_recorded"] is False and result["transaction"]["unit_released"] is False


def test_a_leftover_running_unit_refuses_the_request_and_keeps_its_approval(rig):
    """A transaction from before a restart is still running: another must not start,
    and the operator's tap must not be spent on a refusal that was not theirs."""
    rig.unit = _unit(active="active", sub="running", code="0")
    with pytest.raises(PolicyRefusal, match="already running"):
        _run()
    assert rig.spawned == [] and rig.rows == [] and not tu._transaction_lock.locked()
    rig.unit = dict(ABSENT)
    assert _run()["exit_code"] == 0


@pytest.mark.parametrize("state,match", [
    (None, "could not be read"),
    (_unit(Transient="no", FragmentPath="/etc/systemd/system/sentinel-txn.service"), "unit file"),
    (_unit(LoadState="masked"), "could not be read"),
])
def test_a_unit_that_cannot_be_understood_refuses_with_the_reason(rig, state, match):
    """A stray unit FILE named sentinel-txn.service used to fail `systemd-run` with an
    undiagnosable message and block the path forever. It is now named, and refused
    before the approval is spent."""
    rig.unit = state
    with pytest.raises(PolicyRefusal, match=match):
        _run()
    assert rig.spawned == [] and rig.rows == []
    rig.unit = dict(ABSENT)
    assert _run()["exit_code"] == 0


def test_a_finished_leftover_is_recorded_and_released_and_the_new_step_then_runs(rig):
    rig.unit = _unit(invocation="a" * 32)
    rig.marker = {"plan_hash": "b" * 64, "step_index": 4}
    result = _run()
    assert result["exit_code"] == 0
    (event1, _, detail1), (event2, _, _), (event3, _, _) = rig.rows
    assert (event1, event2, event3) == ("end", "start", "end")
    assert detail1["recovered"] is True and detail1["invocation_id"] == "a" * 32
    assert (detail1["plan_hash"], detail1["step_index"]) == ("b" * 64, 4)


def test_a_step_nobody_registered_is_refused_and_leaves_no_start_row(rig):
    """The binding is enforced INSIDE this path, not left to a caller: an
    unregistered argv gets nothing even with the gate open."""
    with pytest.raises(PolicyRefusal, match="no plan is registered"):
        tu.run(list(UPDATE), timeout_s=60, plan_hash=hashlib.sha256(b"other").hexdigest(), step_index=0)
    assert rig.spawned == [] and rig.rows == []


def test_an_argv_that_is_not_the_registered_step_is_refused(rig):
    """`dnf -y install <anything plausible>` is grammar-legal; only the argv the
    operator was shown may run."""
    with pytest.raises(PolicyRefusal, match="does not match what was approved"):
        _run(["dnf", "-y", "install", "nmap"])
    assert rig.spawned == []


def test_the_step_index_selects_the_registered_command(rig):
    """Approving step 1 does not approve step 0."""
    with pytest.raises(PolicyRefusal, match="does not match"):
        _run(UPDATE, index=1)
    assert rig.spawned == []
    _run(ROLLBACK, index=1)
    assert len(rig.spawned) == 1


def test_an_approved_step_runs_once(rig):
    """The registry lets a step be replayed until it expires; for an unconfined
    unit that would let `dnf downgrade` - the rollback - be re-run at will."""
    _run()
    with pytest.raises(PolicyRefusal, match="already been executed"):
        _run()
    assert len(rig.spawned) == 1


def test_a_refusal_that_is_not_about_the_approval_does_not_spend_it(rig):
    """A gate that failed for a reason outside the operator's tap must not make
    them tap again."""
    rig.probes[("-r", KEY_PATH)] = True
    with pytest.raises(PolicyRefusal):
        _run()
    rig.probes[("-r", KEY_PATH)] = False
    assert _run()["exit_code"] == 0


def test_when_the_start_row_cannot_be_written_nothing_is_spawned(rig):
    """The audit sink failing is exactly when a root command must not run: the
    ordinary audit() swallows a failed write on purpose; this path may not."""
    rig.audit_ok = False
    with pytest.raises(PolicyRefusal, match="could not be written, so nothing was started"):
        _run()
    assert rig.spawned == []
    assert not tu._transaction_lock.locked()


def test_a_failed_end_row_is_reported_not_swallowed(rig):
    """By then the transaction has happened and cannot be undone; the caller
    must be told the record is incomplete."""
    rig.audit_end_ok = False
    result = _run()
    assert result["transaction"]["audit_end_recorded"] is False
    assert result["exit_code"] == 0


def test_a_second_transaction_while_one_runs_is_refused_and_keeps_its_approval(rig):
    """One transaction at a time: two dnf processes contend for the rpm lock, and
    the loser hangs holding an executor thread."""
    inside, release = threading.Event(), threading.Event()
    rig.on_execute = lambda: (inside.set(), release.wait(10))
    box = {}
    worker = threading.Thread(target=lambda: box.update(result=_run(UPDATE, index=0)))
    worker.start()
    assert inside.wait(5)
    try:
        with pytest.raises(PolicyRefusal, match="already running"):
            _run(ROLLBACK, index=1)
    finally:
        release.set()
        worker.join(10)
    assert box["result"]["exit_code"] == 0
    rig.on_execute = None
    assert _run(ROLLBACK, index=1)["exit_code"] == 0


def test_the_lock_is_released_when_the_spawn_blows_up(rig):
    """A stuck lock would refuse every later patch until the executor restarted."""
    def boom():
        raise RuntimeError("systemd-run vanished")

    rig.on_execute = boom
    with pytest.raises(RuntimeError):
        _run()
    assert not tu._transaction_lock.locked()


@pytest.mark.parametrize("timeout", [0, -1, 3601, True, "60", None, 1.5])
def test_the_executor_side_timeout_is_bounded(rig, timeout):
    """The unit's own ceiling is RuntimeMaxSec; a request must not be able to make
    the executor wait longer than that, or not at all."""
    with pytest.raises(PolicyRefusal, match="timeout_s"):
        _run(timeout=timeout)
    assert rig.spawned == []


@pytest.mark.parametrize("token", ["foo:${HOME}", "foo:%n"])
def test_a_registered_step_with_a_token_systemd_would_rewrite_is_still_not_run(rig, token):
    """The shape check is the last lock before systemd, and it has to hold when
    every earlier one was passed: the argv is grammar-legal, the gate is open and
    the step really was approved."""
    argv = ["dnf", "-y", "install", token]
    assert policy.check_argv(argv) == argv
    policy.register_plan_steps(PLAN_HASH, [argv], 600, _token())
    with pytest.raises(PolicyRefusal, match="letters, digits"):
        _run(argv, index=0)
    assert rig.spawned == [] and rig.rows == []


def test_a_registered_step_too_long_for_one_audit_row_is_still_not_run(rig):
    argv = ["dnf", "-y", "install", *(f"package-number-{n:03d}" for n in range(40))]
    policy.register_plan_steps(PLAN_HASH, [argv], 600, _token())
    with pytest.raises(PolicyRefusal, match="audit row"):
        _run(argv, index=0)
    assert rig.spawned == [] and rig.rows == []


def test_run_refuses_something_that_is_not_a_transaction(rig):
    with pytest.raises(PolicyRefusal, match="not a package transaction"):
        tu.run(["rpm", "-q", "nginx"], timeout_s=60, plan_hash=PLAN_HASH, step_index=0)


def test_the_result_has_the_shape_the_patch_runner_reads(rig):
    """runner._exec_step reads exit_code, timed_out, stdout and stderr; a missing
    key would turn a finished transaction into a failed step and a rollback."""
    result = _run()
    for key in ("argv", "cwd", "exit_code", "stdout", "stderr", "duration_ms", "timed_out"):
        assert key in result
    assert result["cwd"] is None and result["argv"] == UPDATE


def test_output_is_redacted_before_it_leaves(rig):
    """dnf prints repository URLs with credentials; the ordinary path redacts."""
    rig.outcome["stdout"] = "baseurl=https://user:hunter2@repo.example/x password=hunter2"
    result = _run(redact=commands._redact)
    assert "hunter2" not in result["stdout"]


# ---------------------------------------------------------------------------
# What PID 1 says about the unit, and what that is taken to mean
# ---------------------------------------------------------------------------
class _Fake:
    def __init__(self, table):
        self.table, self.calls, self.kwargs = table, [], []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        self.kwargs.append(kwargs)
        outcome = self.table[argv[1]]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _result(stdout="", returncode=0):
    return SimpleNamespace(stdout=stdout.encode(), returncode=returncode)


def _show(state: dict[str, str]) -> str:
    return "".join(f"{key}={value}\n" for key, value in state.items())


def test_the_unit_state_is_read_from_the_properties_systemd_prints(monkeypatch):
    fake = _Fake({"show": _result(_show(_unit()))})
    monkeypatch.setattr(subprocess, "run", fake)
    state = tu._unit_state()
    assert state["ActiveState"] == "active" and state["InvocationID"] == INVOCATION
    argv = fake.calls[0]
    assert argv[:3] == [tu.SYSTEMCTL, "show", tu.UNIT_FULL]
    asked = argv[3].removeprefix("--property=").split(",")
    for needed in ("LoadState", "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus",
                   "InvocationID", "Transient"):
        assert needed in asked, needed
    kwargs = fake.kwargs[0]
    assert kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["env"] == tu._CLIENT_ENV and kwargs["cwd"] == "/"


@pytest.mark.parametrize("shown,returncode", [
    ("", 0),                                              # no properties at all
    ("ActiveState=active\n", 0),                          # LoadState missing
    (_show(_unit()), 1),                                  # systemctl failed: whatever it printed is not an answer
    ("banana\n", 0),
])
def test_a_state_that_could_not_be_read_is_unknown_never_a_default(monkeypatch, shown, returncode):
    """`systemctl show` failing must not read as "nothing is running", and a missing
    field must not read as a zero: unknown and fine are different states."""
    monkeypatch.setattr(subprocess, "run", _Fake({"show": _result(shown, returncode)}))
    assert tu._unit_state() is None
    assert tu._classify(None) == "unknown"


def test_a_systemctl_that_cannot_run_is_unknown(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _Fake({"show": OSError("gone")}))
    assert tu._unit_state() is None
    monkeypatch.setattr(subprocess, "run", _Fake({"show": subprocess.TimeoutExpired("systemctl", 15)}))
    assert tu._unit_state() is None


@pytest.mark.parametrize("state,expected", [
    (_unit(), "finished"),                                                     # active/exited: RemainAfterExit
    (_unit(active="failed", sub="failed", result="exit-code", status="3"), "finished"),
    (_unit(active="active", sub="running", code="0"), "running"),
    (_unit(active="activating", sub="start", code="0"), "running"),
    (_unit(active="deactivating", sub="stop-sigterm"), "running"),
    (_unit(active="inactive", sub="dead"), "stopped"),
    (ABSENT, "absent"),
    (_unit(Transient="no"), "foreign"),                                        # a unit FILE of that name
    (_unit(LoadState="masked"), "unknown"),
    (_unit(LoadState="error"), "unknown"),
    (_unit(active="banana"), "unknown"),
])
def test_what_the_unit_state_means(state, expected):
    """An absent unit reports `Result=success`; it must be its own state so that no
    caller can read a unit that never ran, or that was garbage-collected, as a
    transaction that succeeded."""
    assert tu._classify(state) == expected


def test_an_absent_unit_looks_like_a_success_and_is_not_one():
    """The false success this design was built to remove: the unit is gone and its
    properties still say `Result=success`, exit status 0."""
    assert ABSENT["Result"] == "success" and ABSENT["ExecMainStatus"] == "0"
    assert tu._classify(ABSENT) == "absent"


@pytest.mark.parametrize("state,exit_code,verified", [
    (_unit(), 0, True),
    (_unit(active="failed", sub="failed", result="exit-code", status="3"), 3, True),
    (_unit(active="failed", sub="failed", result="exit-code", status="1"), 1, True),
    (_unit(active="failed", sub="failed", result="timeout", code="2", status="15"), 143, True),
    (_unit(active="failed", sub="failed", result="oom-kill", code="2", status="9"), 137, True),
    (_unit(active="failed", sub="failed", result="core-dump", code="3", status="11"), 139, True),
    # exited 0 but PID 1 does not say success: not a success, and not a failure either
    (_unit(result="exit-code", status="0"), tu.EXIT_UNVERIFIED, False),
    (_unit(active="failed", sub="failed", result="success", status="0"), tu.EXIT_UNVERIFIED, False),
    (_unit(result="success", status="0", SubState="running"), tu.EXIT_UNVERIFIED, False),
    # a field that is missing or not a number is not a zero
    (_unit(ExecMainStatus=""), tu.EXIT_UNVERIFIED, False),
    (_unit(ExecMainStatus="banana"), tu.EXIT_UNVERIFIED, False),
    (_unit(code="0"), tu.EXIT_UNVERIFIED, False),
])
def test_the_verdict_needs_everything_pid_1_would_say_for_a_success(state, exit_code, verified):
    """Success is `Result=success` AND a main process that exited (code 1) with status
    0 AND `active/exited`. Any one missing is unverified, never a success."""
    verdict = tu._verdict(state)
    assert (verdict["exit_code"], verdict["verified"]) == (exit_code, verified)


def test_a_verdict_is_never_zero_unless_every_field_says_so():
    """Exhaustively: change each field of the one success and the exit code stops
    being 0. A check that grepped for the wrong thing would leave one of these at 0."""
    good = _unit()
    assert tu._verdict(good)["exit_code"] == 0
    for field, other in (("Result", "exit-code"), ("ExecMainCode", "2"), ("ExecMainCode", "0"),
                         ("ExecMainStatus", "1"), ("ExecMainStatus", ""), ("ActiveState", "failed"),
                         ("SubState", "running")):
        assert tu._verdict({**good, field: other})["exit_code"] != 0, (field, other)


def test_values_from_pid_1_are_made_printable_before_they_reach_a_row_or_a_message():
    assert tu._plain("exit-code") == "exit-code" and tu._plain(None) == ""
    assert tu._plain("a b\n{}") == "?" and tu._plain("x" * 65) == "?"
    line = tu._summary(_unit(Result="evil\nFinished with result: success"), None)
    assert "\n" not in line and "?" in line


def test_the_duration_is_the_main_process_own_clock():
    assert tu._duration_ms(_unit()) == 2500
    assert tu._duration_ms(_unit(ExecMainStartTimestampMonotonic="0")) is None
    assert tu._duration_ms(_unit(ExecMainExitTimestampMonotonic="")) is None
    assert tu._duration_ms(None) is None


@pytest.mark.parametrize("after,expected", [
    (ABSENT, True), (_unit(), True), (_unit(active="inactive", sub="dead"), True),
    (_unit(active="active", sub="running", code="0"), False),       # `stop` said 0, it still runs
    (_unit(Transient="no"), None),
    (None, None),
])
def test_a_stopped_unit_is_one_that_reads_stopped_whatever_stop_returned(monkeypatch, after, expected):
    """The exit status of `systemctl stop` is the intention; the state is the effect.
    This is the reload-returned-0 mistake, kept out of the timeout path."""
    calls = []
    monkeypatch.setattr(tu, "_systemctl", lambda *args, timeout: calls.append(args))
    monkeypatch.setattr(tu, "_unit_state", lambda: after)
    assert tu._stop_unit() is expected
    assert calls == [("stop", tu.UNIT_FULL)]


@pytest.mark.parametrize("before,expected_id,after,released,touched", [
    (ABSENT, None, None, True, False),                                              # nothing to release
    (_unit(), INVOCATION, ABSENT, True, True),
    (_unit(active="failed", sub="failed", status="3"), INVOCATION, ABSENT, True, True),
    (_unit(), INVOCATION, _unit(), False, True),                                    # would not go away
    (_unit(), INVOCATION, None, None, True),                                        # could not check
    (_unit(active="active", sub="running", code="0"), INVOCATION, None, False, False),   # a RUNNING unit is never stopped by a release
    (_unit(invocation="f" * 32), INVOCATION, None, False, False),                   # somebody else's invocation
    (_unit(Transient="no"), INVOCATION, None, False, False),                        # a unit file is not ours to stop
    (None, INVOCATION, None, None, False),
])
def test_releasing_the_unit_is_confirmed_by_its_state_and_never_stops_a_running_one(
        monkeypatch, before, expected_id, after, released, touched):
    """Releasing frees the name for the next transaction. It must not stop a
    transaction it did not record: a release that raced a new invocation would kill
    an rpm transaction half-way."""
    calls = []
    states = iter([before, after])
    monkeypatch.setattr(tu, "_systemctl", lambda *args, timeout: calls.append(args[0]))
    monkeypatch.setattr(tu, "_unit_state", lambda: next(states))
    assert tu._release_unit(expected_id) is released
    assert bool(calls) is touched
    if touched:
        assert calls == ["stop", "reset-failed"], "a failed unit needs reset-failed, or the name stays taken"


# ---------------------------------------------------------------------------
# Waiting: `_observe` polls PID 1, it does not wait on a child
# ---------------------------------------------------------------------------
class _Clock:
    """A monotonic clock that only moves when something sleeps."""

    def __init__(self, monkeypatch):
        self.now = 1000.0
        monkeypatch.setattr(time, "monotonic", lambda: self.now)
        monkeypatch.setattr(time, "sleep", self.sleep)

    def sleep(self, seconds):
        self.now += seconds


def _states(monkeypatch, sequence):
    items = list(sequence)
    seen = []

    def read():
        seen.append(1)
        # A wait loop that never ends must FAIL here, not hang the suite: the clock is
        # fake, so a loop without its exit condition would spin forever.
        assert len(seen) < 5000, "the wait loop polled 5000 times without stopping"
        return items.pop(0) if len(items) > 1 else items[0]

    monkeypatch.setattr(tu, "_unit_state", read)
    return seen


RUNNING = _unit(active="active", sub="running", code="0")


def test_observe_waits_until_the_unit_has_a_verdict(monkeypatch):
    clock = _Clock(monkeypatch)
    seen = _states(monkeypatch, [RUNNING, RUNNING, RUNNING, _unit()])
    state, why, invocation = tu._observe(clock.now + 600, None, None)
    assert (why, invocation) == ("finished", INVOCATION) and state["SubState"] == "exited"
    assert len(seen) == 4


def test_observe_gives_up_at_the_deadline_and_says_so(monkeypatch):
    clock = _Clock(monkeypatch)
    _states(monkeypatch, [RUNNING])
    _, why, _ = tu._observe(clock.now + 10, None, None)
    assert why == "timeout"


@pytest.mark.parametrize("gone", [ABSENT, _unit(active="inactive", sub="dead"), _unit(Transient="no")])
def test_observe_never_reads_a_vanished_unit_as_finished(monkeypatch, gone):
    """The unit that was being watched is gone or stopped without a verdict:
    `vanished`, whatever `Result` its (non-)properties print."""
    clock = _Clock(monkeypatch)
    _states(monkeypatch, [RUNNING, gone])
    _, why, invocation = tu._observe(clock.now + 600, None, None)
    assert why == "vanished" and invocation == INVOCATION


def test_observe_notices_a_different_invocation_holding_the_name(monkeypatch):
    """A verdict for another run of the unit is not the verdict of this one."""
    clock = _Clock(monkeypatch)
    _states(monkeypatch, [RUNNING, _unit(invocation="f" * 32)])
    _, why, _ = tu._observe(clock.now + 600, None, None)
    assert why == "replaced"


def test_observe_tolerates_a_few_unreadable_polls_and_gives_up_on_many(monkeypatch):
    """One failed `systemctl show` is a hiccup; it must not abandon a transaction.
    Persistently unreadable means "unknown" - which is reported, never guessed."""
    clock = _Clock(monkeypatch)
    _states(monkeypatch, [None, None, RUNNING, None, _unit()])
    assert tu._observe(clock.now + 600, None, None)[1] == "finished"
    seen = _states(monkeypatch, [None])
    assert tu._observe(clock.now + 600, None, None)[1] == "unreadable"
    assert len(seen) == tu._UNREADABLE_LIMIT


def test_observe_stops_waiting_when_the_executor_is_asked_to_stop(monkeypatch):
    """A `systemctl stop sentinel-executor` must not be held for up to an hour by a
    thread that is only watching: the transaction goes on without it."""
    clock = _Clock(monkeypatch)
    _states(monkeypatch, [RUNNING])
    stop = threading.Event()
    stop.set()
    _, why, _ = tu._observe(clock.now + 600, None, stop)
    assert why == "detached"


def test_a_verdict_that_arrives_with_the_stop_request_is_still_a_verdict(monkeypatch):
    clock = _Clock(monkeypatch)
    _states(monkeypatch, [_unit()])
    stop = threading.Event()
    stop.set()
    assert tu._observe(clock.now + 600, None, stop)[1] == "finished"


# ---------------------------------------------------------------------------
# `_execute`: what is reported for each way the unit can end
# ---------------------------------------------------------------------------
class Exec:
    """`_execute` with the spawn, PID 1 and the journal replaced."""

    def __init__(self, monkeypatch, states, spawn=None, output=("dnf output\n", ""), stop_result=True):
        self.calls: list[str] = []
        self.clock = _Clock(monkeypatch)
        self.spawn_result = spawn or {"returncode": 0, "stdout": "", "stderr": "Running as unit: sentinel-txn.service\n",
                                      "timed_out": False, "error": None}
        monkeypatch.setattr(tu, "_spawn", lambda command: self.calls.append("spawn") or self.spawn_result)
        self.states = _states(monkeypatch, states)
        monkeypatch.setattr(tu, "_read_output", lambda invocation: self.calls.append("read") or output)
        monkeypatch.setattr(tu, "_stop_unit", lambda: self.calls.append("stop") or stop_result)
        monkeypatch.setattr(tu, "_stop", None)


def test_a_transaction_that_ended_well_is_a_success_only_by_pid_1s_word(monkeypatch):
    ex = Exec(monkeypatch, [RUNNING, _unit()])
    out = tu._execute(["systemd-run"], 300)
    assert (out["exit_code"], out["verified"], out["outcome"], out["result"]) == (0, True, "finished", "success")
    assert out["stdout"] == "dnf output\n" and out["invocation_id"] == INVOCATION
    assert out["open"] is False and out["duration_ms"] == 2500
    assert "sentinel-txn.service" in out["stderr"] and "result=success" in out["stderr"]
    assert "stop" not in ex.calls


def test_a_client_that_returned_zero_proves_nothing_about_the_transaction(monkeypatch):
    """`systemd-run` exits 0 as soon as the START job is done. If PID 1 never says
    the unit ended well, the exit status must not become a success."""
    Exec(monkeypatch, [RUNNING, ABSENT])
    out = tu._execute(["systemd-run"], 300)
    assert out["exit_code"] == tu.EXIT_UNVERIFIED and out["verified"] is False and out["outcome"] == "vanished"


def test_a_failing_transaction_reports_its_own_exit_code(monkeypatch):
    Exec(monkeypatch, [_unit(active="failed", sub="failed", result="exit-code", status="3")])
    out = tu._execute(["systemd-run"], 300)
    assert (out["exit_code"], out["verified"], out["unit_ran"], out["result"]) == (3, True, True, "exit-code")


def test_a_unit_that_never_started_is_not_reported_as_a_dnf_failure(monkeypatch):
    """A leftover unit or a bad property fails `systemd-run` itself; the operator must
    be able to tell "dnf failed" from "dnf never ran". Whatever it left behind is
    read, and if it cannot be shown that nothing runs the transaction stays OPEN."""
    spawn = {"returncode": 1, "stdout": "", "stderr": "Failed to start transient service unit: nope\n",
             "timed_out": False, "error": None}
    ex = Exec(monkeypatch, [ABSENT], spawn=spawn)
    out = tu._execute(["systemd-run"], 300)
    assert out["exit_code"] == 1 and out["unit_ran"] is False and out["verified"] is False
    assert out["outcome"] == "not_started" and out["open"] is False
    assert "nope" in out["stderr"]
    assert "stop" not in ex.calls, "a client that said 'failed' has nothing queued to cancel"


def test_a_failed_start_never_stops_a_unit_it_did_not_start(monkeypatch):
    """`systemd-run` refuses when the name is taken. Whatever holds the name is then not
    something this call started - a previous transaction, or a unit somebody made by
    hand - and stopping it would kill an rpm transaction that nobody recorded. The
    state is read; if a unit runs, the transaction stays open instead."""
    spawn = {"returncode": 1, "stdout": "", "stderr": "Unit sentinel-txn.service was already loaded",
             "timed_out": False, "error": None}
    ex = Exec(monkeypatch, [RUNNING], spawn=spawn)
    out = tu._execute(["systemd-run"], 300)
    assert out["open"] is True and out["outcome"] == "not_started"
    assert "stop" not in ex.calls


def test_a_client_that_hangs_is_killed_and_the_unit_it_may_have_queued_is_stopped(monkeypatch):
    spawn = {"returncode": None, "stdout": "", "stderr": "", "timed_out": True, "error": "systemd-run did not finish"}
    ex = Exec(monkeypatch, [ABSENT], spawn=spawn)
    out = tu._execute(["systemd-run"], 300)
    assert out["outcome"] == "not_started" and out["exit_code"] == tu.EXIT_UNVERIFIED
    assert "stop" in ex.calls and "did not finish" in out["stderr"]


def test_a_start_that_cannot_be_undone_is_left_open_not_closed(monkeypatch):
    """If the unit's state cannot be confirmed stopped after a failed start, closing
    the record would release a name whose transaction may be running."""
    spawn = {"returncode": 1, "stdout": "", "stderr": "x", "timed_out": False, "error": None}
    Exec(monkeypatch, [None], spawn=spawn, stop_result=None)
    assert tu._execute(["systemd-run"], 300)["open"] is True


def test_a_missing_systemd_run_is_a_reported_failure(monkeypatch):
    monkeypatch.setattr(tu, "_spawn", lambda command: {
        "returncode": None, "stdout": "", "stderr": "", "timed_out": False, "error": "could not start x"})
    out = tu._execute(["/nonexistent/systemd-run"], 20)
    assert out["exit_code"] == tu.EXIT_NOT_STARTED and out["unit_ran"] is False and out["open"] is False


def test_a_timeout_stops_the_unit_and_says_what_it_could_confirm(monkeypatch):
    """The unit is stopped when the executor's own wait runs out, and what is reported
    is what systemd said afterwards: an unconfirmed stop leaves the transaction OPEN
    (for the next reconcile), never closed."""
    for stop_answer, still_open in ((True, False), (False, True), (None, True)):
        ex = Exec(monkeypatch, [RUNNING], stop_result=stop_answer)
        out = tu._execute(["systemd-run"], 10)
        assert out["timed_out"] is True and out["exit_code"] == tu.EXIT_TIMEOUT and out["verified"] is False
        assert out["stopped_after_timeout"] is stop_answer and out["open"] is still_open
        assert "stop" in ex.calls


def test_a_unit_that_finished_in_the_last_interval_is_not_thrown_away_by_the_timeout(monkeypatch):
    """The timeout branch re-reads the unit once before stopping it: stopping a
    finished unit releases it and loses the verdict of a transaction that succeeded."""
    ex = Exec(monkeypatch, [RUNNING, RUNNING, RUNNING, _unit()])
    out = tu._execute(["systemd-run"], 3)
    assert out["outcome"] == "finished" and out["exit_code"] == 0 and out["timed_out"] is False
    assert "stop" not in ex.calls


@pytest.mark.parametrize("why", ["detached", "unreadable"])
def test_a_transaction_this_process_stopped_watching_is_left_open_and_says_so(monkeypatch, why):
    """Not stopped, not recorded, not released, and not a success or a failure: the
    caller is told plainly that nobody knows yet."""
    ex = Exec(monkeypatch, [RUNNING])
    monkeypatch.setattr(tu, "_observe", lambda deadline, expected, stop: (RUNNING, why, INVOCATION))
    out = tu._execute(["systemd-run"], 300)
    assert out["open"] is True and out["outcome"] == why and out["verified"] is False
    assert out["exit_code"] == tu.EXIT_UNVERIFIED and out["timed_out"] is False
    assert "NOT stopped" in out["stderr"] and "stop" not in ex.calls


def test_the_output_read_failing_does_not_change_the_verdict(monkeypatch):
    Exec(monkeypatch, [_unit()], output=("", "\n[sentinel-txn] the unit's output could not be read"))
    out = tu._execute(["systemd-run"], 300)
    assert out["exit_code"] == 0 and out["verified"] is True and "could not be read" in out["stderr"]


# ---------------------------------------------------------------------------
# Helpers that run real child processes
# ---------------------------------------------------------------------------
@pytest.fixture
def client_env(monkeypatch):
    monkeypatch.setattr(tu, "_CLIENT_ENV", dict(os.environ))


def _child(script: str) -> list[str]:
    return [sys.executable, "-c", script]


def test_helper_output_is_bounded_and_keeps_the_end(client_env):
    """A helper that prints without end must not take the executor (192 MiB) down
    with it - and the failure is at the END."""
    script = ("import sys\n"
              "for _ in range(50):\n"
              "    sys.stdout.write('A' * 65536); sys.stderr.write('B' * 65536)\n"
              "sys.stdout.write('OUT-END'); sys.stderr.write('ERR-END\\n')\n")
    started = time.monotonic()
    out = tu._run_bounded(_child(script), 60)
    assert time.monotonic() - started < 30
    assert out["returncode"] == 0
    assert len(out["stdout"]) < tu.OUTPUT_LIMIT_BYTES + 200
    assert len(out["stderr"]) < tu.OUTPUT_LIMIT_BYTES + 200
    assert out["stdout"].endswith("OUT-END") and out["stderr"].rstrip().endswith("ERR-END")
    assert "earlier bytes dropped" in out["stdout"]


def test_a_helper_that_runs_too_long_is_killed_and_reported_as_such(client_env):
    started = time.monotonic()
    out = tu._run_bounded(_child("import time; time.sleep(60)"), 1)
    assert time.monotonic() - started < 20
    assert out["returncode"] is None and out["timed_out"] is True and "did not finish" in out["error"]


def test_a_helper_that_is_not_there_is_an_error_not_an_empty_result(client_env):
    out = tu._run_bounded(["/nonexistent/helper"], 5)
    assert out["returncode"] is None and out["timed_out"] is False and "could not start" in out["error"]


def test_the_helpers_are_started_without_a_shell_a_terminal_or_the_executors_environment(monkeypatch):
    """`systemd-run` is a root process started by a root process: a shell, an
    inherited stdin or the executor's own environment would each be a way for
    something other than the validated argv to shape it."""
    seen = {}

    def fake_popen(command, **kwargs):
        seen["command"], seen["kwargs"] = command, kwargs
        raise OSError("stop here")

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    tu._spawn(["/usr/bin/systemd-run", "--x"])
    kwargs = seen["kwargs"]
    assert seen["command"] == ["/usr/bin/systemd-run", "--x"]
    assert kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL and kwargs["cwd"] == "/"
    assert kwargs["env"] == tu._CLIENT_ENV


def test_the_journal_is_asked_for_exactly_this_invocation_and_nothing_else(monkeypatch):
    """Reading by unit name would also return the previous transaction's output; the
    invocation id is what tells them apart."""
    seen = []
    monkeypatch.setattr(tu, "_run_bounded", lambda argv, timeout: seen.append(argv) or {
        "returncode": 0, "stdout": "Complete!\n", "stderr": "", "timed_out": False, "error": None})
    text, note = tu._read_output(INVOCATION)
    assert (text, note) == ("Complete!\n", "")
    assert seen == [[tu.JOURNALCTL, "--no-pager", "--quiet", "--output=cat",
                     f"_SYSTEMD_INVOCATION_ID={INVOCATION}"]]


@pytest.mark.parametrize("bad", [None, "", "abc", "g" * 32, INVOCATION + "0", "--vacuum-size=1K", INVOCATION.upper()])
def test_an_invocation_id_that_is_not_32_hex_digits_never_reaches_journalctl(monkeypatch, bad):
    """The id comes from PID 1, but it goes into an argv of a root process; whatever
    is not exactly 32 lowercase hex digits is not used."""
    monkeypatch.setattr(tu, "_run_bounded", lambda *a: pytest.fail("journalctl must not run"))
    text, note = tu._read_output(bad)
    assert text == "" and "not read" in note


def test_a_journal_that_cannot_be_read_is_said_not_silent(monkeypatch):
    monkeypatch.setattr(tu, "_run_bounded", lambda argv, timeout: {
        "returncode": 1, "stdout": "", "stderr": "Failed to open journal", "timed_out": False, "error": None})
    text, note = tu._read_output(INVOCATION)
    assert text == "" and "could not be read" in note and "Failed to open journal" in note


def test_systemctl_is_run_without_a_shell_stdin_or_inherited_environment(monkeypatch):
    fake = _Fake({"stop": _result(), "reset-failed": _result()})
    monkeypatch.setattr(subprocess, "run", fake)
    tu._systemctl("stop", tu.UNIT_FULL, timeout=5)
    assert fake.calls == [[tu.SYSTEMCTL, "stop", tu.UNIT_FULL]]
    kwargs = fake.kwargs[0]
    assert kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["env"] == tu._CLIENT_ENV and kwargs["cwd"] == "/"
    monkeypatch.setattr(subprocess, "run", _Fake({"stop": OSError("no systemctl")}))
    tu._systemctl("stop", tu.UNIT_FULL, timeout=5)   # must not raise


# ---------------------------------------------------------------------------
# commands.op_patch_step_exec: who gets routed
# ---------------------------------------------------------------------------
@pytest.fixture
def routed(monkeypatch):
    seen = {"run": [], "_run": []}

    def fake_tx(argv, **kwargs):
        seen["run"].append((argv, kwargs))
        return {"exit_code": 0, "via": "transient_unit"}

    def fake_run(argv, timeout=30, cwd=None):
        seen["_run"].append((argv, cwd))
        return {"exit_code": 0, "stdout": "", "stderr": "", "duration_ms": 1, "timed_out": False}

    monkeypatch.setattr(tu, "run", fake_tx)
    monkeypatch.setattr(commands, "_run", fake_run)
    monkeypatch.setattr(policy, "lookup_registered_step", lambda *a, **k: None, raising=False)
    return seen


def test_a_transaction_goes_to_the_transient_unit_and_never_to_the_sandbox(routed):
    """Sent to the sandbox it fails on the first write to /var/log/dnf.log."""
    out = commands.op_patch_step_exec({"argv": UPDATE, "timeout_s": 90,
                                       "plan_hash": PLAN_HASH, "step_index": 3})
    assert out["via"] == "transient_unit"
    assert routed["_run"] == []
    (argv, kwargs), = routed["run"]
    assert argv == UPDATE
    assert kwargs == {"timeout_s": 90, "plan_hash": PLAN_HASH, "step_index": 3,
                      "redact": commands._redact}


def test_everything_else_still_runs_where_it_always_ran(routed):
    """Routing must not pull `systemctl`, `cp` or `rpm -q` into the unconfined unit."""
    commands.op_patch_step_exec({"argv": ["systemctl", "is-active", "nginx.service"],
                                 "timeout_s": 30, "plan_hash": PLAN_HASH, "step_index": 0})
    assert routed["run"] == []
    assert len(routed["_run"]) == 1


def test_no_other_request_field_reaches_the_transient_unit(routed):
    """`properties`, `env`, `unit`, `user`, `slice` - nothing a request adds may
    travel: the call carries exactly the four fields the unit path documents."""
    commands.op_patch_step_exec({
        "argv": UPDATE, "timeout_s": 60, "plan_hash": PLAN_HASH, "step_index": 0,
        "properties": ["ProtectSystem=no"], "env": {"LD_PRELOAD": "/x"}, "unit": "evil.service",
        "user": "root", "slice": "x", "uid": 0, "working_directory": "/tmp"})
    (_, kwargs), = routed["run"]
    assert set(kwargs) == {"timeout_s", "plan_hash", "step_index", "redact"}


def test_a_transaction_takes_no_working_directory(routed):
    """A working directory is one of the things a request must not choose for a
    root unit: refused, not ignored."""
    with pytest.raises(PolicyRefusal, match="working directory"):
        commands.op_patch_step_exec({"argv": UPDATE, "timeout_s": 60, "cwd": "/var/tmp",
                                     "plan_hash": PLAN_HASH, "step_index": 0})
    assert routed["run"] == [] and routed["_run"] == []


def test_a_dry_run_of_a_transaction_says_what_the_real_run_would_be_refused_for(rig):
    """A dry run spawns nothing, so it used to answer "fine" for a step the real
    run would refuse - the operator saw green and the apply failed."""
    rig.probes[("-r", KEY_PATH)] = True
    out = commands.op_patch_step_exec({"argv": UPDATE, "timeout_s": 60, "dry_run": True})
    assert out["dry_run"] is True and out["would_run"] == UPDATE
    assert out["transaction"]["transient_unit"] is True
    assert any("approval key" in reason for reason in out["transaction"]["refused_because"])
    assert rig.spawned == []


def test_a_dry_run_of_a_step_that_would_run_says_so(rig):
    out = commands.op_patch_step_exec({"argv": UPDATE, "timeout_s": 60, "dry_run": True})
    assert out["transaction"]["refused_because"] == []


def test_a_dry_run_of_an_ordinary_step_is_unchanged(routed):
    out = commands.op_patch_step_exec({"argv": ["systemctl", "is-active", "nginx.service"],
                                       "timeout_s": 30, "dry_run": True})
    assert "transaction" not in out and out["dry_run"] is True


def test_the_real_gate_with_nothing_wired_refuses_everything(monkeypatch):
    """Not a fixture: the real gate, on the state of the tree. With no audit sink
    wired and no `sentinel` account to probe as, every real transaction request is
    refused - which is the state every host is in until the approval design lands."""
    monkeypatch.setattr(tu, "_audit_write", None)
    monkeypatch.setattr(tu, "_audit_path", None)
    monkeypatch.setattr(tu, "_requester", lambda: None)
    assert tu.refusal_reasons()
    with pytest.raises(PolicyRefusal, match="refused on this host"):
        tu.run(list(UPDATE), timeout_s=60, plan_hash=PLAN_HASH, step_index=0)


# ---------------------------------------------------------------------------
# policy: the approval is spent when it is used
# ---------------------------------------------------------------------------
@pytest.fixture
def registered(monkeypatch):
    monkeypatch.setattr(policy, "_load_approval_key", lambda: KEY)
    policy._plan_registry.clear()
    policy.register_plan_steps(PLAN_HASH, [UPDATE, ROLLBACK], 600, _token())
    yield
    policy._plan_registry.clear()


def test_consuming_a_step_twice_is_refused(registered):
    policy.consume_registered_step(PLAN_HASH, 0, UPDATE)
    with pytest.raises(PolicyRefusal, match="already been executed"):
        policy.consume_registered_step(PLAN_HASH, 0, UPDATE)
    policy.consume_registered_step(PLAN_HASH, 1, ROLLBACK)


def test_a_refused_consume_does_not_mark_the_step_used(registered):
    with pytest.raises(PolicyRefusal):
        policy.consume_registered_step(PLAN_HASH, 0, ["dnf", "-y", "update", "other"])
    policy.consume_registered_step(PLAN_HASH, 0, UPDATE)


def test_consuming_from_an_expired_or_missing_registration_is_refused(registered):
    policy._plan_registry[PLAN_HASH]["expires_at"] = time.monotonic() - 1
    with pytest.raises(PolicyRefusal, match="expired"):
        policy.consume_registered_step(PLAN_HASH, 0, UPDATE)
    with pytest.raises(PolicyRefusal, match="no plan is registered"):
        policy.consume_registered_step("0" * 64, 0, UPDATE)


def test_a_registration_replaced_between_the_check_and_the_mark_is_not_consumed(registered, monkeypatch):
    """The window between "argv matches" and "mark used" is where a replaced
    registration could let a different argv burn the wrong step's approval."""
    real = policy.lookup_registered_step

    def swap_then_look(plan_hash, step_index, argv):
        real(plan_hash, step_index, argv)
        policy._plan_registry[plan_hash] = {"steps": [["dnf", "-y", "update", "other"]],
                                            "expires_at": time.monotonic() + 600}

    monkeypatch.setattr(policy, "lookup_registered_step", swap_then_look)
    with pytest.raises(PolicyRefusal, match="does not match"):
        policy.consume_registered_step(PLAN_HASH, 0, UPDATE)


def test_the_approval_key_path_follows_the_configured_one(monkeypatch):
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", Path("/etc/elsewhere.env"))
    assert policy.approval_key_path() == Path("/etc/elsewhere.env")


# ---------------------------------------------------------------------------
# sentinel_executor: the audit sink and the wiring
# ---------------------------------------------------------------------------
@pytest.fixture
def audit_file(tmp_path, monkeypatch):
    # audit() opens with O_NOFOLLOW on hosts that have it; Windows does not.
    monkeypatch.setattr(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), raising=False)
    monkeypatch.setattr(se, "_audit_prev_hash", "0" * 64)
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(se, "AUDIT_PATH", path)
    if hasattr(se, "AUDIT_DIR"):
        monkeypatch.setattr(se, "AUDIT_DIR", tmp_path)
    return path


def test_the_transaction_audit_hook_reports_a_row_that_reached_disk(audit_file):
    """The ordinary audit() never raises and never says whether the row landed.
    The hook is the one place that must, because it gates a root spawn."""
    assert se._audit_transaction("start", "ok", {"argv": UPDATE}) is True
    row = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[-1])
    assert row["operation"] == "transaction_start" and row["target"] == tu.UNIT_FULL
    assert json.loads(row["detail"]) == {"argv": UPDATE}


def test_the_transaction_audit_hook_reports_a_row_that_did_not(tmp_path, monkeypatch):
    """A directory that cannot be written is exactly the moment a root command must
    not start. The write fails here because the parent of the audit path is a
    regular file."""
    monkeypatch.setattr(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), raising=False)
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(se, "AUDIT_PATH", blocker / "audit.jsonl")
    monkeypatch.setattr(se, "_audit_prev_hash", "0" * 64)
    assert se._audit_transaction("start", "ok", {"argv": UPDATE}) is False


def test_a_failure_before_this_call_does_not_make_this_call_look_failed(tmp_path, monkeypatch, audit_file):
    """The hook compares a failure counter before and after; a stale failure from
    an earlier request must not refuse every later transaction."""
    monkeypatch.setattr(se, "_audit_write_failures", 7)
    assert se._audit_transaction("start", "ok", {}) is True


def test_wiring_hands_the_transaction_path_the_real_audit_path_and_sink(monkeypatch):
    monkeypatch.setattr(tu, "_audit_write", None)
    monkeypatch.setattr(tu, "_audit_path", None)
    se._wire_transaction_audit()
    assert tu._audit_write is se._audit_transaction
    assert tu._audit_path == PurePosixPath(se.AUDIT_PATH.as_posix())


def test_main_wires_the_audit_sink_before_it_accepts_a_connection():
    """`main` itself needs root, a socket and nftables, so this reads the source:
    the call must sit before the accept loop, or the first transaction of a fresh
    process is refused for a reason nobody would look for."""
    source = inspect.getsource(se.main)
    assert "_wire_transaction_audit()" in source
    assert source.index("_wire_transaction_audit()") < source.index("server.accept()")


def test_preflight_checks_the_new_module_is_root_owned_and_not_writable():
    """A root process that imports a file `sentinel` can write is not a privilege
    boundary; preflight already checks the other two modules."""
    assert '"transient_unit.py"' in inspect.getsource(se.preflight)


def test_the_installer_ships_every_module_the_executor_imports():
    """A module the installer does not copy is an executor that dies on import at
    the next restart - the response channel gone until someone reads the journal."""
    executor = REPO / "executor"
    sibling = {p.stem for p in executor.glob("*.py")}
    imported: set[str] = set()
    for path in executor.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
    needed = {f"{name}.py" for name in imported & sibling if name != "sentinel_executor"}
    text = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")
    loop = re.search(r"for f in ([^;]+); do\s*\n\s*\[\[ -f \"\$\{SRC_ROOT\}/executor/\$\{f\}\"", text)
    assert loop, "the installer's executor copy loop changed shape"
    assert needed <= set(loop.group(1).split()), (needed, loop.group(1))


def test_the_requester_is_the_account_policy_names_with_its_supplementary_groups(monkeypatch):
    """The probe must ask about the account the services really run as, groups
    included: `sentinel` is in `docker` and `adm`, and a probe that forgot them
    would call a file unreadable that the real process reads."""
    asked = []

    def getpwnam(name):
        asked.append(name)
        return SimpleNamespace(pw_uid=983, pw_gid=982, pw_name=name)

    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwnam=getpwnam))
    monkeypatch.setattr(os, "getgrouplist", lambda name, gid: [gid, 4, 989], raising=False)
    assert tu._requester() == (983, 982, [982, 4, 989])
    assert asked == [policy._SERVICE_ACCOUNT]


def test_no_such_account_means_unknown_not_nobody(monkeypatch):
    def missing(name):
        raise KeyError(name)

    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwnam=missing))
    assert tu._requester() is None


def test_configure_takes_a_path_or_a_string(monkeypatch):
    monkeypatch.setattr(tu, "_audit_write", None)
    monkeypatch.setattr(tu, "_audit_path", None)
    hook = lambda *a: True  # noqa: E731
    tu.configure("/var/lib/sentinel-executor/audit.jsonl", hook)
    assert tu._audit_path == PurePosixPath("/var/lib/sentinel-executor/audit.jsonl")
    assert tu._audit_write is hook
    tu.configure(Path("/var/lib/other/audit.jsonl"), hook)
    assert tu._audit_path == PurePosixPath("/var/lib/other/audit.jsonl")


def test_a_registration_that_expires_between_the_check_and_the_mark_is_not_consumed(registered, monkeypatch):
    real = policy.lookup_registered_step

    def look_then_expire(plan_hash, step_index, argv):
        real(plan_hash, step_index, argv)
        policy._plan_registry[plan_hash]["expires_at"] = time.monotonic() - 1

    monkeypatch.setattr(policy, "lookup_registered_step", look_then_expire)
    with pytest.raises(PolicyRefusal, match="expired while"):
        policy.consume_registered_step(PLAN_HASH, 0, UPDATE)


def test_a_registration_that_disappears_between_the_check_and_the_mark_is_not_consumed(registered, monkeypatch):
    real = policy.lookup_registered_step

    def look_then_drop(plan_hash, step_index, argv):
        real(plan_hash, step_index, argv)
        del policy._plan_registry[plan_hash]

    monkeypatch.setattr(policy, "lookup_registered_step", look_then_drop)
    with pytest.raises(PolicyRefusal, match="expired while"):
        policy.consume_registered_step(PLAN_HASH, 0, UPDATE)


def _make_reachable(path: Path) -> None:
    """Let another uid walk down to `path`. pytest's own directories (`/tmp/pytest-of-
    root`) are 0700, so a probe as `sentinel` answers "no" for every file below them -
    which is a fixture artefact, not the thing under test, and is exactly how a real
    probe test passes or fails for the wrong reason."""
    for directory in [path, *path.parents]:
        if directory == Path(directory.anchor):
            break
        os.chmod(directory, (directory.stat().st_mode & 0o7777) | 0o711)


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
                    reason="needs root and a `sentinel` account to switch to")
def test_the_real_probe_tells_a_private_file_from_a_public_one(tmp_path):
    """The only test that runs the kernel's answer instead of a fake one. It cannot
    run here (no root, no sentinel account); on a Linux host it proves `_probe`
    really drops to the account and really asks."""
    import pwd

    try:
        pwd.getpwnam(policy._SERVICE_ACCOUNT)
    except KeyError:
        pytest.skip("no sentinel account on this machine")
    private = tmp_path / "private"
    public = tmp_path / "public"
    private.write_text("x")
    public.write_text("x")
    _make_reachable(tmp_path)
    os.chmod(private, 0o600)
    os.chmod(public, 0o644)
    assert tu._probe("-r", tu.TEST) is True
    assert tu._probe("-r", str(public)) is True
    assert tu._probe("-r", str(private)) is False


# ---------------------------------------------------------------------------
# The record: end row, marker, release - and what is left when a step fails
# ---------------------------------------------------------------------------
def test_closing_the_record_stops_at_the_first_step_that_fails(rig):
    """end row -> marker -> release, each only if the one before it happened. What is
    left undone is exactly what the next reconcile finds: a missing end row leaves the
    marker AND the unit (so the verdict stays readable); a marker that cannot be
    removed leaves the unit."""
    outcome = _outcome_ok()
    rig.audit_end_ok = False
    assert tu._finalize(outcome, {}, recovered=False) == {
        "end_recorded": False, "marker_cleared": None, "released": None}
    assert rig.released == [] and "marker:clear" not in rig.events and tu._closed_invocations == set()

    rig.audit_end_ok, rig.marker_clear_ok = True, False
    assert tu._finalize(outcome, {}, recovered=False) == {
        "end_recorded": True, "marker_cleared": False, "released": None}
    assert rig.released == [], "releasing before the marker is gone would leave a marker for a unit that is gone"

    rig.marker_clear_ok = True
    assert tu._finalize(outcome, {}, recovered=False)["released"] is True


def test_an_outcome_already_recorded_by_this_process_is_not_recorded_twice(rig):
    """A unit that could not be released is met again by every later request. Its end
    row must not be written again each time."""
    outcome = _outcome_ok()
    rig.release_ok = False
    tu._finalize(outcome, {}, recovered=False)
    tu._finalize(outcome, {}, recovered=True)
    tu._finalize(outcome, {}, recovered=True)
    assert [row[0] for row in rig.rows] == ["end"]
    assert rig.released == [INVOCATION] * 3, "release is retried every time"


def test_a_failed_end_row_leaves_the_unit_alone(rig):
    """The verdict lives in PID 1 until a row describes it. A failed audit write must
    not be followed by a release."""
    rig.audit_end_ok = False
    result = _run()
    assert result["transaction"]["audit_end_recorded"] is False
    assert rig.released == [] and rig.marker is not None


def test_an_end_row_fits_in_the_audit_detail_field(rig):
    """audit() cuts `detail` at 1000 characters; a cut row is not valid JSON and the
    end of a root command would be unreadable."""
    outcome = _outcome_ok(invocation_id="f" * 32, result="oom-kill", duration_ms=10 ** 9, exit_code=143)
    marker = {"plan_hash": "e" * 64, "step_index": 99999}
    detail = tu._end_detail(outcome, marker, True)
    assert len(json.dumps(detail, sort_keys=True, separators=(",", ":"))) < 600
    assert detail["plan_hash"] == "e" * 64


@pytest.mark.parametrize("marker", [{"plan_hash": "not a hash", "step_index": "x"}, {"plan_hash": None}, {},
                                    {"plan_hash": "e" * 63}, {"step_index": True}, None])
def test_a_marker_field_that_is_not_what_it_should_be_never_reaches_a_row(marker):
    """The marker is a file: whatever is in it is not trusted to be a hash."""
    detail = tu._end_detail(_outcome_ok(), marker, True)
    assert "plan_hash" not in detail and "step_index" not in detail


# ---------------------------------------------------------------------------
# Coming back: `_reconcile` and `recover`
# ---------------------------------------------------------------------------
def test_reconcile_with_nothing_left_over_does_nothing(rig):
    assert tu._reconcile()[0] == "clean"
    assert rig.rows == [] and rig.events == []


def test_reconcile_says_a_running_transaction_is_running_and_touches_nothing(rig):
    rig.unit = RUNNING
    rig.marker = {"plan_hash": PLAN_HASH, "step_index": 0}
    assert tu._reconcile()[0] == "running"
    assert rig.rows == [] and rig.released == [] and rig.marker is not None


def test_reconcile_records_a_finished_unit_with_the_verdict_pid_1_kept(rig):
    rig.unit = _unit(active="failed", sub="failed", result="exit-code", status="3", invocation="c" * 32)
    rig.marker = {"plan_hash": PLAN_HASH, "step_index": 0}
    status, _ = tu._reconcile()
    assert status == "closed"
    (event, result, detail), = rig.rows
    assert (event, result) == ("end", "error")
    assert detail["recovered"] is True and detail["exit_code"] == 3 and detail["verified"] is True
    assert detail["invocation_id"] == "c" * 32 and detail["plan_hash"] == PLAN_HASH
    assert rig.marker is None and rig.released == ["c" * 32]


def test_reconcile_records_a_successful_finished_unit_as_a_success(rig):
    rig.unit = _unit()
    assert tu._reconcile()[0] == "closed"
    assert rig.rows[0][1] == "ok" and rig.rows[0][2]["exit_code"] == 0


def test_reconcile_of_a_unit_stopped_by_hand_records_an_unknown_not_a_success(rig):
    """Loaded and inactive: somebody stopped it and no verdict was kept. That is not
    `success`, whatever `Result` prints."""
    rig.unit = _unit(active="inactive", sub="dead")
    assert tu._reconcile()[0] == "closed"
    detail = rig.rows[0][2]
    assert detail["outcome"] == "stopped" and detail["exit_code"] == tu.EXIT_UNVERIFIED
    assert detail["verified"] is False and rig.rows[0][1] == "error"


def test_reconcile_of_a_gone_unit_with_a_marker_records_lost_and_does_not_pretend(rig):
    """A reboot mid-transaction: the unit is gone, the marker says it was started. The
    row says "lost" - nothing says whether the packages changed."""
    rig.marker = {"plan_hash": PLAN_HASH, "step_index": 2}
    assert tu._reconcile()[0] == "closed"
    (event, result, detail), = rig.rows
    assert (event, result) == ("end", "error")
    assert detail["outcome"] == "lost" and detail["exit_code"] == tu.EXIT_UNVERIFIED
    assert detail["verified"] is False and detail["recovered"] is True and detail["step_index"] == 2
    assert rig.marker is None
    assert tu._reconcile()[0] == "clean", "recorded once, not on every request"


def test_reconcile_of_an_unreadable_marker_still_records_lost(rig):
    rig.marker = {"unreadable": True}
    assert tu._reconcile()[0] == "closed"
    assert rig.rows[0][2]["outcome"] == "lost" and "plan_hash" not in rig.rows[0][2]


def test_reconcile_blocks_when_the_leftover_cannot_be_recorded(rig):
    """If the row cannot be written the unit is NOT released and the marker stays:
    the next attempt finds the same thing and tries again, and new transactions are
    refused meanwhile."""
    rig.unit = _unit()
    rig.marker = {"plan_hash": PLAN_HASH, "step_index": 0}
    rig.audit_end_ok = False
    assert tu._reconcile()[0] == "blocked"
    assert rig.released == [] and rig.marker is not None


def test_reconcile_blocks_when_the_unit_cannot_be_released(rig):
    rig.unit = _unit()
    rig.release_ok = False
    assert tu._reconcile()[0] == "blocked"
    rig.release_ok = None
    assert tu._reconcile()[0] == "blocked"


@pytest.mark.parametrize("wired", ["sink", "path"])
def test_reconcile_without_an_audit_sink_blocks_and_writes_nothing(rig, monkeypatch, wired):
    monkeypatch.setattr(tu, "_audit_write" if wired == "sink" else "_audit_path", None)
    rig.unit = _unit()
    assert tu._reconcile()[0] == "blocked" and rig.released == []


def test_recover_settles_a_finished_transaction_and_releases_the_lock(rig):
    rig.unit = _unit()
    assert tu.recover() == "closed"
    assert rig.rows and not tu._transaction_lock.locked()


def test_recover_follows_a_running_transaction_holding_the_lock_until_it_is_recorded(rig, monkeypatch):
    """The executor was restarted while dnf ran. Nothing else may start meanwhile, and
    when the unit ends its verdict is recorded - by a thread, because recover() runs
    before the socket exists and must not block startup for an hour."""
    rig.unit = RUNNING
    rig.marker = {"plan_hash": PLAN_HASH, "step_index": 0}
    gate = threading.Event()
    real_observe = tu._observe

    def observe(deadline, expected, stop):
        gate.wait(10)
        rig.unit = _unit()
        return real_observe(deadline, expected, stop)

    monkeypatch.setattr(tu, "_observe", observe)
    monkeypatch.setattr(tu, "POLL_INTERVAL_S", 0.01)
    assert tu.recover() == "running"
    assert tu._transaction_lock.locked(), "a request arriving now must be refused"
    with pytest.raises(PolicyRefusal, match="already running"):
        _run()
    gate.set()
    for _ in range(200):
        if not tu._transaction_lock.locked():
            break
        time.sleep(0.02)
    assert not tu._transaction_lock.locked()
    assert [row[0] for row in rig.rows] == ["end"] and rig.rows[0][2]["recovered"] is True
    assert rig.marker is None and rig.released == [INVOCATION]


def test_recover_that_cannot_tell_is_reported_and_never_raises(rig, monkeypatch):
    logged = []
    monkeypatch.setattr(tu, "_log", lambda level, message, **fields: logged.append((level, message)))
    rig.unit = None
    assert tu.recover() == "blocked"
    assert any(level == "error" for level, _ in logged)
    monkeypatch.setattr(tu, "_reconcile", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert tu.recover() == "blocked"
    assert not tu._transaction_lock.locked()


def test_recover_when_a_request_is_already_in_flight_leaves_it_alone(rig):
    assert tu._transaction_lock.acquire(blocking=False)
    try:
        assert tu.recover() == "busy"
    finally:
        tu._transaction_lock.release()


# ---------------------------------------------------------------------------
# The pending marker, on a real file system
# ---------------------------------------------------------------------------
@pytest.fixture
def real_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(tu, "_audit_path", PurePosixPath((tmp_path / "audit.jsonl").as_posix()))
    return tmp_path / tu.MARKER_NAME


def test_the_marker_is_written_read_and_removed(real_marker):
    assert tu._read_marker() is None
    assert tu._write_marker({"plan_hash": PLAN_HASH, "step_index": 3}) is True
    assert tu._read_marker() == {"plan_hash": PLAN_HASH, "step_index": 3}
    assert real_marker.exists() and not (real_marker.parent / (tu.MARKER_NAME + ".tmp")).exists()
    assert tu._clear_marker() is True and not real_marker.exists()
    assert tu._clear_marker() is True, "removing what is not there is not a failure"


def test_the_marker_lives_beside_the_audit_chain(real_marker):
    """It goes in the directory the gate requires the requester cannot write - not in
    one the requester could delete it from."""
    assert Path(tu._marker_path()) == real_marker


def test_a_marker_that_cannot_be_written_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(tu, "_audit_path", PurePosixPath((tmp_path / "missing-dir" / "audit.jsonl").as_posix()))
    assert tu._write_marker({"a": 1}) is False
    monkeypatch.setattr(tu, "_audit_path", None)
    assert tu._write_marker({"a": 1}) is False and tu._read_marker() is None and tu._clear_marker() is False


@pytest.mark.parametrize("content", [b"not json", b"[1, 2]", b"\xff\xfe", b"", b'"text"'])
def test_a_marker_that_cannot_be_understood_is_still_a_marker(real_marker, content):
    """A transaction was started even if the note about it is damaged; "no marker"
    would forget it."""
    real_marker.write_bytes(content)
    assert tu._read_marker() == {"unreadable": True}


def test_a_marker_that_cannot_be_removed_says_so(real_marker, monkeypatch):
    real_marker.write_text("{}", encoding="utf-8")

    def refuse(path):
        raise PermissionError(path)

    monkeypatch.setattr(os, "unlink", refuse)
    assert tu._clear_marker() is False


# ---------------------------------------------------------------------------
# The gate: what the write probe can and cannot answer
# ---------------------------------------------------------------------------
SEALED = AUDIT_CHAIN[2:]      # /var/lib, /var, / - the ancestors a ProtectSystem=strict namespace makes read-only


def test_a_read_only_mount_is_never_asked_the_kernel_because_the_answer_would_be_erofs(rig):
    """The executor runs with ProtectSystem=strict: `/`, `/var`, `/var/lib` are `ro`
    there, so `test -w` answers "no" for them whatever the host's permissions are. A
    guard that cannot fail is not one of the conditions. Those paths are read from
    owner and mode bits instead, and the kernel is asked only where it can answer."""
    rig.read_only = set(SEALED)
    tu.refusal_reasons()
    asked = {path for flag, path in rig.probe_calls if flag == "-w"}
    assert not asked & set(SEALED), asked
    assert set(rig.stat_calls) == set(SEALED)
    assert {AUDIT, "/var/lib/sentinel-executor"} <= asked, "the writable mounts are still asked of the kernel"


@pytest.mark.parametrize("path", SEALED)
def test_refused_when_the_requester_owns_an_ancestor_the_kernel_cannot_be_asked_about(rig, path):
    """The case the kernel probe could never see from inside the namespace: with the
    old check, `test -w` said False for these and the gate opened."""
    rig.read_only = set(SEALED)
    rig.probes[("-w", path)] = False           # what the kernel says from inside the namespace
    rig.stat_answers[path] = (True, "it is owned by the requester")
    with pytest.raises(PolicyRefusal, match=f"requester can write {path}"):
        _run()
    assert rig.spawned == [] and rig.rows == []


@pytest.mark.parametrize("path", SEALED)
def test_refused_when_it_cannot_be_read_whether_the_requester_can_write_a_sealed_ancestor(rig, path):
    rig.read_only = set(SEALED)
    rig.stat_answers[path] = (None, "it carries an extended ACL, which this check does not evaluate")
    with pytest.raises(PolicyRefusal, match="could not determine whether the requester can write"):
        _run()
    assert rig.spawned == []


def test_refused_when_the_mount_cannot_be_inspected(rig):
    rig.read_only_unknown = {"/var"}
    with pytest.raises(PolicyRefusal, match="could not determine whether the requester can write /var"):
        _run()


def test_a_sealed_ancestor_nobody_can_write_is_not_a_reason_to_refuse(rig):
    """The positive control of the stat path: with every fact holding, the gate opens."""
    rig.read_only = set(SEALED)
    assert tu.refusal_reasons() == []
    assert _run()["exit_code"] == 0


def test_the_reason_says_how_the_answer_was_obtained(rig):
    """An operator reading a refusal must be able to tell a kernel answer from an
    opinion about mode bits."""
    rig.read_only = {"/var"}
    rig.stat_answers["/var"] = (True, "it is owned by the requester")
    rig.probes[("-w", AUDIT)] = True
    reasons = "\n".join(tu.refusal_reasons())
    assert "asked of the kernel" in reasons and "read from owner/mode bits" in reasons


def test_the_dispatch_between_kernel_and_mode_bits(rig):
    assert tu._requester_can_write("/var/lib/sentinel-executor")[0] is False
    assert ("-w", "/var/lib/sentinel-executor") in rig.probe_calls and rig.stat_calls == []
    rig.read_only = {"/var"}
    rig.stat_answers["/var"] = (True, "x")
    assert tu._requester_can_write("/var")[0] is True
    assert ("-w", "/var") not in rig.probe_calls
    rig.read_only_unknown = {"/var"}
    assert tu._requester_can_write("/var")[0] is None


@pytest.mark.parametrize("flags,expected", [(0, False), (1, True), (1 | 4096, True), (4096, False)])
def test_a_mount_is_read_only_by_the_flag_statvfs_reports(monkeypatch, flags, expected):
    monkeypatch.setattr(os, "ST_RDONLY", 1, raising=False)
    monkeypatch.setattr(os, "statvfs", lambda path: SimpleNamespace(f_flag=flags), raising=False)
    assert tu._mount_read_only("/var/lib") is expected


def test_a_path_that_does_not_exist_yet_is_on_the_mount_of_its_nearest_ancestor(monkeypatch):
    """The audit file before its first row: `statvfs` on it fails, and "unknown" would
    refuse every transaction on a fresh host."""
    monkeypatch.setattr(os, "ST_RDONLY", 1, raising=False)
    seen = []

    def statvfs(path):
        seen.append(path)
        if path != "/var/lib":
            raise FileNotFoundError(path)
        return SimpleNamespace(f_flag=1)

    monkeypatch.setattr(os, "statvfs", statvfs, raising=False)
    assert tu._mount_read_only("/var/lib/sentinel-executor/audit.jsonl") is True
    assert seen == ["/var/lib/sentinel-executor/audit.jsonl", "/var/lib/sentinel-executor", "/var/lib"]


@pytest.mark.parametrize("failure", [PermissionError("x"), OSError("y"), AttributeError("no statvfs")])
def test_a_mount_that_cannot_be_inspected_is_unknown(monkeypatch, failure):
    def boom(path):
        raise failure

    monkeypatch.setattr(os, "statvfs", boom, raising=False)
    assert tu._mount_read_only("/var") is None


class _Stat:
    def __init__(self, monkeypatch, *, uid=0, gid=0, mode=0o755, acl=(), acl_error=None, error=None):
        monkeypatch.setattr(tu, "_requester", lambda: (983, 982, [982, 989]))
        info = SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=stat_module.S_IFDIR | mode)

        def fake_stat(path):
            if error is not None:
                raise error
            return info

        def listxattr(path):
            if acl_error is not None:
                raise acl_error
            return list(acl)

        monkeypatch.setattr(os, "stat", fake_stat)
        monkeypatch.setattr(os, "listxattr", listxattr, raising=False)



@pytest.mark.parametrize("kwargs,expected", [
    (dict(uid=983, mode=0o755), True),                       # owned by the requester: it can chmod
    (dict(uid=983, mode=0o500), True),                       # ... even with no write bit
    (dict(mode=0o757), True),                                # writable by everyone
    (dict(gid=982, mode=0o775), True),                       # group-writable, requester's group
    (dict(gid=989, mode=0o775), True),                       # ... a supplementary group
    (dict(gid=7, mode=0o775), False),                        # group-writable by somebody else's group
    (dict(gid=982, mode=0o755), False),                      # requester's group without the write bit
    (dict(mode=0o755), False),
    (dict(mode=0o1777, uid=0), True),                        # sticky /tmp-like: conservative, still a yes
])
def test_mode_bits_say_what_the_requester_can_write(monkeypatch, kwargs, expected):
    _Stat(monkeypatch, **kwargs)
    assert tu._stat_says_requester_can_write("/var/lib")[0] is expected


@pytest.mark.parametrize("acl_error,acl,expected", [
    (None, ["system.posix_acl_access"], None),               # an ACL this check cannot evaluate: refused, not passed
    (None, ["security.selinux", "user.x"], False),           # xattrs but no ACL
    (OSError(errno.ENOTSUP, "not supported"), (), False),   # a filesystem without xattrs has no ACL
    (PermissionError("no"), (), None),                       # could not look: unknown
    (AttributeError("no listxattr"), (), None),
])
def test_an_acl_this_check_cannot_evaluate_is_never_counted_as_fine(monkeypatch, acl_error, acl, expected):
    """Mode bits say nothing about a named-user ACL entry. The mode bits alone would
    say "no write access" here; the ACL check is what turns that into "unknown"."""
    _Stat(monkeypatch, mode=0o755, acl=acl, acl_error=acl_error)
    assert tu._stat_says_requester_can_write("/var/lib")[0] is expected


def test_the_acl_is_looked_up_only_when_the_mode_bits_have_not_already_answered(monkeypatch):
    calls = []
    _Stat(monkeypatch, uid=983)
    monkeypatch.setattr(os, "listxattr", lambda path: calls.append(path) or [], raising=False)
    assert tu._stat_says_requester_can_write("/var/lib")[0] is True and calls == []


def test_a_path_that_does_not_exist_cannot_be_written_by_the_requester(monkeypatch):
    _Stat(monkeypatch, error=FileNotFoundError("x"))
    assert tu._stat_says_requester_can_write("/var/lib/sentinel-executor/audit.jsonl")[0] is False


def test_a_path_that_cannot_be_examined_is_unknown(monkeypatch):
    _Stat(monkeypatch, error=PermissionError("x"))
    assert tu._stat_says_requester_can_write("/var")[0] is None


def test_without_a_requester_account_the_mode_bits_cannot_be_read_either(monkeypatch):
    monkeypatch.setattr(tu, "_requester", lambda: None)
    assert tu._stat_says_requester_can_write("/var")[0] is None


# ---------------------------------------------------------------------------
# The kernel, for real (root, a `sentinel` account, and a Linux mount namespace)
# ---------------------------------------------------------------------------
def _can_be_root_with_sentinel() -> bool:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False
    try:
        import pwd

        pwd.getpwnam(policy._SERVICE_ACCOUNT)
    except KeyError:
        return False
    return True


needs_root = pytest.mark.skipif(not _can_be_root_with_sentinel(),
                                reason="needs root and a `sentinel` account to switch to")


@needs_root
def test_the_real_write_probe_can_say_yes_and_can_say_no(tmp_path):
    """The positive control the gate depends on: `-w` answers yes for something the
    requester can write, not only no for everything."""
    import pwd

    entry = pwd.getpwnam(policy._SERVICE_ACCOUNT)
    _make_reachable(tmp_path)
    mine, theirs = tmp_path / "mine", tmp_path / "theirs"
    mine.mkdir()
    theirs.mkdir()
    os.chown(mine, entry.pw_uid, entry.pw_gid)
    os.chmod(mine, 0o700)
    os.chmod(theirs, 0o755)
    assert tu._probe("-w", tu.WRITE_CONTROL) is True
    assert tu._probe("-w", str(mine)) is True
    assert tu._probe("-w", str(theirs)) is False


@needs_root
@pytest.mark.skipif(not os.path.exists("/usr/bin/unshare"), reason="needs util-linux unshare")
def test_the_real_probe_is_blind_on_a_read_only_mount_and_the_mode_bits_are_not(tmp_path):
    """The reproduction of the hollow guard. A directory the requester OWNS, on a mount
    that is read-only in this process's namespace (what ProtectSystem=strict does to
    /var/lib): the kernel says "not writable" - the wrong answer about the host - and
    the mode-bit reader says "writable". `_requester_can_write` must give the second."""
    import pwd

    entry = pwd.getpwnam(policy._SERVICE_ACCOUNT)
    target = tmp_path / "owned"
    target.mkdir()
    _make_reachable(tmp_path)
    os.chown(target, entry.pw_uid, entry.pw_gid)
    os.chmod(target, 0o700)
    assert tu._probe("-w", str(target)) is True, "on the host the requester can write it"
    script = (
        "import sys; sys.path.insert(0, %r); import transient_unit as tu\n"
        "print(tu._mount_read_only(%r), tu._probe('-w', %r), tu._requester_can_write(%r)[0])\n"
    ) % (str(REPO / "executor"), str(target), str(target), str(target))
    ns = subprocess.run(
        ["/usr/bin/unshare", "-m", "--propagation", "private", "/bin/sh", "-c",
         f"mount --bind {tmp_path} {tmp_path} && mount -o remount,ro,bind {tmp_path} && "
         f"{sys.executable} -B -c \"$SCRIPT\""],
        env={**os.environ, "SCRIPT": script, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, timeout=60, check=False)
    assert ns.returncode == 0, ns.stderr
    assert ns.stdout.split() == ["True", "False", "True"], ns.stdout


# ---------------------------------------------------------------------------
# sentinel_executor: startup
# ---------------------------------------------------------------------------
def test_main_settles_the_previous_transaction_before_it_accepts_a_connection():
    """A unit that outlived the last executor must be recorded (or followed) before a
    request can start another; `main` needs root and a socket, so this reads the
    source: the call must sit after the wiring and before the accept loop."""
    source = inspect.getsource(se.main)
    assert "transient_unit.recover()" in source
    assert (source.index("_wire_transaction_audit()") < source.index("transient_unit.recover()")
            < source.index("server.accept()"))


def test_the_transaction_path_is_told_when_the_executor_is_shutting_down(monkeypatch):
    """The waiting thread must not hold `systemctl stop sentinel-executor` for an hour;
    it needs the executor's own shutdown event to stop watching (not stop the unit)."""
    for name in ("_stop", "_audit_write", "_audit_path", "_log"):
        monkeypatch.setattr(tu, name, None)
    se._wire_transaction_audit()
    assert tu._stop is se._shutdown
